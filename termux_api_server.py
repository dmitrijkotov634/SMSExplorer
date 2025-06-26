import asyncio
import base64
import json
import logging
import re
from dataclasses import dataclass, field
from io import BytesIO
from typing import Optional
from urllib.parse import urljoin

import brotli
import bs4
import htmlmin
import httpx
from PIL import Image

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

logger = logging.getLogger("server")
logger.setLevel(logging.INFO)

formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')

file_handler = logging.FileHandler("server.log")
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)

executor_lock = asyncio.Lock()

HEADERS = {
    "User-Agent": "NokiaC3-00/08.70 Profile/MIDP-2.1 Configuration/CLDC-1.1"
}

MAX_SMS_LENGTH = 160
SMS_LIMIT_PER_REQUEST = 100


@dataclass
class Context:
    latest_id: Optional[int] = field(default=None)


context: dict[str, Context] = {}


# noinspection PyBroadException
async def execute(*args, timeout=7):
    async with executor_lock:
        process = await asyncio.create_subprocess_exec(
            *args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
            logger.debug(f"{' '.join(map(str, args))} stdout.decode()")
            return stdout.decode()
        except Exception:
            process.kill()


async def listen_sms():
    while True:
        messages = []

        try:
            response = await execute(
                "termux-sms-list",
                "--message-limit=1",
                "--message-type=inbox",
            )

            messages = json.loads(response)
        except Exception as e:
            logger.error(f"Failed to retrieve SMS messages: {e}")

        for message in messages:
            phone_number = message["number"]

            if phone_number not in context:
                context[phone_number] = Context()

            ctx = context[message["number"]]

            if ctx.latest_id is None:
                ctx.latest_id = message["_id"]
                continue

            if message["_id"] > ctx.latest_id:
                logger.info(
                    f"New SMS received from {phone_number}, ID: {message['_id']}, length: {len(message['body'])}")
                yield message["number"], ctx, message["body"]
                ctx.latest_id = message["_id"]


@dataclass
class RequestParams:
    raw: bool = False
    no_limit: bool = False
    images: bool = False
    image_quality: int = 1
    preserve_alpha: bool = False

    @staticmethod
    def from_tokens(tokens: list[str]) -> tuple["RequestParams", str | None]:
        flags = RequestParams()
        url = None

        for token in tokens:
            token_upper = token.strip().upper()
            if token.lower().startswith("http"):
                url = token.strip()
            elif token_upper == "RAW":
                flags.raw = True
            elif token_upper == "NOLIMIT":
                flags.no_limit = True
            elif token_upper == "IMG":
                flags.images = True
            elif token_upper == "PNG":
                flags.images = True
                flags.preserve_alpha = True
            elif token_upper.startswith("IMGQ"):
                try:
                    flags.images = True
                    quality = int(token_upper[4:])
                    if 1 <= quality <= 95:
                        flags.image_quality = quality
                except ValueError:
                    pass

        return flags, url


async def fetch_image_base64(client, url: str, params: RequestParams) -> str | None:
    logger.debug(f"Fetching image: {url}")
    resp = await client.get(url, timeout=5.0)
    resp.raise_for_status()

    img = Image.open(BytesIO(resp.content))

    if params.preserve_alpha and img.mode in ("RGBA", "LA"):
        img = img.convert("RGBA")
        buffer = BytesIO()
        img.save(buffer, format="PNG", optimize=True)
        img_base64 = base64.b64encode(buffer.getvalue()).decode("utf-8")
        return f"data:image/png;base64,{img_base64}"
    else:
        img = img.convert("RGB")
        buffer = BytesIO()
        img.save(buffer, format="JPEG", quality=params.image_quality)
        img_base64 = base64.b64encode(buffer.getvalue()).decode("utf-8")
        return f"data:image/jpeg;base64,{img_base64}"


async def extract_useful_html(raw_html: str, params: RequestParams, base_url: str) -> str:
    soup = bs4.BeautifulSoup(raw_html, "html.parser")

    for tag in soup(["script", "style", "meta", "iframe", "noscript", "video", "title"]):
        tag.decompose()

    img_tags = []
    if params.images:
        img_tags = [tag for tag in soup.find_all("img") if tag.get("src")]
    else:
        for tag in soup.find_all("img"):
            tag.decompose()

    async with httpx.AsyncClient(follow_redirects=True) as client:
        tasks = [fetch_image_base64(client, urljoin(base_url, tag["src"]), params) for tag in img_tags]
        base64_results = await asyncio.gather(*tasks, return_exceptions=True)

    for tag, data_uri in zip(img_tags, base64_results):
        if isinstance(data_uri, Exception):
            logger.warning(f"Image conversion failed: {data_uri}")
            tag.decompose()
        elif data_uri:
            tag["src"] = data_uri
        else:
            tag.decompose()

    head_tag = soup.find("head")
    if head_tag and not head_tag.get_text(strip=True) and not head_tag.find_all():
        head_tag.decompose()

    for tag in soup.find_all(True):
        allowed_attrs = {"action", "method", "type", "name", "value", "href", "id", "placeholder", "src"}
        tag.attrs = {k: v for k, v in tag.attrs.items() if k in allowed_attrs}

    cleaned_html = str(soup)
    cleaned_html = re.sub(r'<!DOCTYPE[^>]*>', '', cleaned_html)

    print(cleaned_html)
    return htmlmin.minify(
        cleaned_html,
        remove_comments=True,
        remove_empty_space=False,
        reduce_empty_attributes=True,
        remove_all_empty_space=False,
        remove_optional_attribute_quotes=True,
    )


class Base114:
    SYMBOL_TABLE = [
        "@", "£", "$", "¥", "è", "é", "ù", "ì", "ò", "Ç", "\n", "Ø", "ø", "Å", "å", "_", "Æ", "æ", "ß", "É",
        "!", "\"", "#", "¤", "%", "&", "'", "(", ")", "*", "+", ",", "-", ".", "/", "0", "1", "2", "3", "4", "5",
        "6", "7", "8", "9", ":", ";", "<", "=", ">", "?", "¡", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J",
        "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "Ä", "Ö", "Ñ", "Ü",
        "\u00A7", "¿", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r",
        "s", "t", "u", "v", "w", "x", "y", "z", "ä", "ö", "ñ", "ü", "à"
    ]

    @classmethod
    def encode(cls, data: bytes) -> str:
        if not data:
            return ""

        num = int.from_bytes(data, 'big')
        result = []

        while num > 0:
            result.append(cls.SYMBOL_TABLE[num % 114])
            num //= 114

        return ''.join(reversed(result))

    @classmethod
    def decode(cls, encoded: str) -> bytes:
        if not encoded:
            return b""

        symbol_to_value = {symbol: i for i, symbol in enumerate(cls.SYMBOL_TABLE)}

        num = 0
        for char in encoded:
            if char not in symbol_to_value:
                raise ValueError(f"Invalid character: {char}")
            num = num * 114 + symbol_to_value[char]

        if num == 0:
            return b"\x00"

        byte_length = (num.bit_length() + 7) // 8
        return num.to_bytes(byte_length, 'big')


def decode_sms_data(encoded: str) -> str:
    compressed = Base114.decode(encoded)
    decompressed = brotli.decompress(compressed)
    return decompressed.decode('utf-8')


def encode_sms_data(text: str) -> str:
    text_bytes = text.encode('utf-8')
    compressed = brotli.compress(text_bytes, quality=11)
    return Base114.encode(compressed)


def make_chunks_with_prefix(text: str) -> list[str]:
    estimated_parts = (len(text) + (MAX_SMS_LENGTH - 6) - 1) // (MAX_SMS_LENGTH - 6)

    while True:
        prefix_len = len(f"{estimated_parts}/{estimated_parts}#")
        chunk_size = MAX_SMS_LENGTH - prefix_len
        real_parts = (len(text) + chunk_size - 1) // chunk_size
        if real_parts == estimated_parts:
            break
        estimated_parts = real_parts

    chunks = []
    prefix_len = len(f"{estimated_parts}/{estimated_parts}#")
    chunk_size = MAX_SMS_LENGTH - prefix_len

    pos = 0
    part_num = 1

    while pos < len(text):
        end_pos = min(pos + chunk_size, len(text))

        if end_pos < len(text) and text[end_pos - 1] == '\n':
            end_pos -= 1

        part = text[pos:end_pos]
        prefix = f"{part_num}/{estimated_parts}#"
        chunks.append(prefix + part)

        pos = end_pos
        part_num += 1

    logger.info(f"Created {len(chunks)} SMS chunks from {len(text)} characters")
    return chunks


async def send_multipart_sms(
        number: str,
        text: str,
        limit: int = SMS_LIMIT_PER_REQUEST
) -> bool:
    chunks = make_chunks_with_prefix(text)

    if len(chunks) > limit:
        return False

    logger.info(f"Sending {len(chunks)} SMS chunks to {number}")

    for i, chunk in enumerate(chunks, 1):
        await execute("termux-sms-send", "-n", number, chunk)
        logger.info(f"SMS chunk {i}/{len(chunks)} sent to {number}")

    return True


async def process_request(number: str, decoded_request: str):
    logger.info(f"Processing request from {number}: {decoded_request}")

    tokens = decoded_request.split()
    params, url = RequestParams.from_tokens(tokens)

    async with httpx.AsyncClient(
            timeout=20,
            headers=HEADERS,
            follow_redirects=True,
            verify=False
    ) as client:
        try:
            response = await client.get(url)
            logger.info(f"HTTP response received for {number}: status {response.status_code}")
            final_url = str(response.url)
            html = response.text if params.raw else await extract_useful_html(response.text, params, final_url)
            html_with_base = f'<base href="{final_url}">{html}'
            if not await send_multipart_sms(number, encode_sms_data(html_with_base)):
                await send_multipart_sms(number, encode_sms_data("Reached limit"))
        except httpx.TimeoutException:
            await send_multipart_sms(number, encode_sms_data("Request timeout"))
        except httpx.HTTPError as e:
            await send_multipart_sms(number, encode_sms_data(f"HTTP error: {e}"))
        except Exception as e:
            logger.error(f"Unexpected error processing request: {e}")
            await send_multipart_sms(number, encode_sms_data("Server error"))


async def main():
    logger.info("SMS server started")
    async for number, ctx, content in listen_sms():
        try:
            decoded_request = decode_sms_data(content)
            await process_request(number, decoded_request)
        except Exception as e:
            logger.exception("Exception while handling SMS from %s: %s", number, e)


if __name__ == '__main__':
    asyncio.run(main())
