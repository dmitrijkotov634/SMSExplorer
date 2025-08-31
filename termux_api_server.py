import asyncio
import base64
import json
import logging
import os
import re
from dataclasses import dataclass, field
from io import BytesIO
from typing import Optional
from urllib.parse import urljoin, urlparse, urlunparse

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

http_client = httpx.AsyncClient(
    timeout=25,
    follow_redirects=True,
    verify=False
)

ALLOWED_HTML_ATTRS = {
    "action",
    "method",
    "type",
    "name",
    "value",
    "href",
    "id",
    "placeholder",
    "src",
    "rows",
    "cols",
    "disabled"
}

MAX_SMS_LENGTH = 160
SMS_LIMIT_PER_REQUEST = 100

DOMAIN_MAPPING: dict[str, tuple[str, Optional[int]]] = {}


def parse_target(target_string: str) -> tuple[str, Optional[int]]:
    if ':' in target_string:
        host, port_str = target_string.rsplit(':', 1)
        try:
            port = int(port_str)
            return host, port
        except ValueError:
            return target_string, None
    return target_string, None


def load_host_mapping(file_path: str = "host_mapping.txt"):
    if not os.path.exists(file_path):
        return

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    parts = line.split()
                    if len(parts) >= 2:
                        domain = parts[0].lower()
                        target = parts[1]

                        target_host, target_port = parse_target(target)
                        DOMAIN_MAPPING[domain] = (target_host, target_port)

        logger.info(f"Loaded {len(DOMAIN_MAPPING)} host mappings from {file_path}")
    except Exception as e:
        logger.error(f"Error loading host mappings: {e}")


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
    no_base: bool = False
    method: str = "GET"

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
            elif token_upper == "NOBASE":
                flags.no_base = True
                flags.raw = True
                flags.no_limit = True
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
            elif token_upper in ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"]:
                flags.method = token_upper

        return flags, url


async def fetch_image_base64(
        client: httpx.AsyncClient,
        url: str,
        params: RequestParams,
        headers: dict[str, str]
) -> str | None:
    logger.debug(f"Fetching image: {url}")
    resp = await client.get(url, timeout=5.0, headers=headers)
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


async def extract_useful_html(
        raw_html: str,
        params: RequestParams,
        base_url: str,
        headers: dict[str, str],
        allowed_tags: list[str]
) -> str:
    soup = bs4.BeautifulSoup(raw_html, "html.parser")

    for tag in soup(["script", "style", "meta", "iframe", "noscript", "video", "title"]):
        if tag.name not in allowed_tags:
            tag.decompose()

    img_tags = []
    if params.images:
        img_tags = [tag for tag in soup.find_all("img") if tag.get("src")]
    elif "img" not in allowed_tags:
        for tag in soup.find_all("img"):
            tag.decompose()

    tasks = [fetch_image_base64(http_client, urljoin(base_url, tag["src"]), params, headers) for tag in img_tags]
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
        tag.attrs = {k: v for k, v in tag.attrs.items() if k in ALLOWED_HTML_ATTRS}

    cleaned_html = str(soup)
    cleaned_html = re.sub(r'<!DOCTYPE[^>]*>', '', cleaned_html)

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
    print(text)
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
            if end_pos == pos:
                end_pos = min(pos + chunk_size, len(text))

        part = text[pos:end_pos]
        prefix = f"{part_num}/{estimated_parts}#"
        chunks.append(prefix + part)

        pos = end_pos
        part_num += 1

    logger.info(f"Created {len(chunks)} SMS chunks from {len(text)} characters")
    return chunks


async def send_multipart_sms(number: str, parts: str | list[str]):
    chunks = parts if isinstance(parts, list) else make_chunks_with_prefix(parts)

    logger.info(f"Sending {len(chunks)} SMS chunks to {number}")

    for i, chunk in enumerate(chunks, 1):
        await execute("termux-sms-send", "-n", number, chunk)
        logger.info(f"SMS chunk {i}/{len(chunks)} sent to {number}")

    return True


def reverse_redirect_domain(url: str) -> str:
    if not DOMAIN_MAPPING or not url:
        return url

    try:
        parsed = urlparse(url)
        current_host = parsed.hostname
        current_port = parsed.port

        if not current_host:
            return url

        for original_domain, (target_host, target_port) in DOMAIN_MAPPING.items():
            host_match = current_host == target_host
            port_match = (target_port is None and current_port is None) or (current_port == target_port)

            if host_match and port_match:
                new_netloc = original_domain

                if '@' in parsed.netloc:
                    userinfo = parsed.netloc.split('@')[0]
                    new_netloc = f"{userinfo}@{new_netloc}"

                new_parsed = parsed._replace(netloc=new_netloc)
                reversed_url = urlunparse(new_parsed)

                logger.info(f"Host reversed: {current_host}:{current_port or 'default'} -> {original_domain}")
                return reversed_url

    except Exception as e:
        logger.error(f"Error reversing domain: {e}")

    return url


def redirect_domain(url: str) -> str:
    if not DOMAIN_MAPPING or not url:
        return url

    try:
        parsed = urlparse(url)
        original_host = parsed.hostname

        if not original_host:
            return url

        if original_host.lower() in DOMAIN_MAPPING:
            target_host, target_port = DOMAIN_MAPPING[original_host.lower()]

            if target_port:
                new_netloc = f"{target_host}:{target_port}"
            else:
                new_netloc = target_host

            if '@' in parsed.netloc:
                userinfo = parsed.netloc.split('@')[0]
                new_netloc = f"{userinfo}@{new_netloc}"

            new_parsed = parsed._replace(netloc=new_netloc)
            redirected_url = urlunparse(new_parsed)

            logger.info(f"Host redirected: {original_host} -> {target_host}:{target_port or 'default'}")
            return redirected_url

    except Exception as e:
        logger.error(f"Error redirecting domain: {e}")

    return url


async def process_request(number: str, decoded_request: str):
    logger.info(f"Processing request from {number}: {decoded_request}")

    try:
        if '\n' in decoded_request:
            headers_part, body_part = decoded_request.split('\n', 1)
            body = body_part.strip() if body_part.strip() else None
        else:
            headers_part = decoded_request
            body = None

        tokens = headers_part.split()
        params, url = RequestParams.from_tokens(tokens)

        redirected_url = redirect_domain(url)

        parsed_url = urlparse(redirected_url)
        check_url = f"{parsed_url.scheme}://{parsed_url.netloc}"

        # noinspection PyBroadException
        try:
            check_response = await http_client.patch(
                url=check_url,
                headers=HEADERS
            )
            needs_phone_header = check_response.headers.get("SE-Phone-Number-Required", "").lower() == "true"
            allow_images = check_response.headers.get("SE-Allow-Images", "").lower() == "true"
            allowed_tags = []
            for header, value in check_response.headers.items():
                header_lower = header.lower()
                if header_lower.startswith("se-allow-tag-") and value.lower() == "true":
                    tag = header_lower.replace("se-allow-tag-", "")
                    allowed_tags.append(tag)
        except Exception:
            needs_phone_header = False
            allow_images = False
            allowed_tags = []

        if allow_images:
            params.images = True

        headers = {
            **HEADERS,
            **({"SE-Phone-Number": number} if needs_phone_header else {})
        }

        request_kwargs = {
            "method": params.method,
            "url": redirected_url,
            "headers": headers
        }

        if body and params.method in ["POST", "PUT", "PATCH"]:
            request_kwargs["data"] = body
            request_kwargs["headers"] = {
                **headers,
                "Content-Type": "application/x-www-form-urlencoded"
            }

        response = await http_client.request(**request_kwargs)
        logger.info(f"HTTP response received for {number}: status {response.status_code}")
        final_url = reverse_redirect_domain(str(response.url))
        html = response.text if params.raw else await extract_useful_html(
            response.text,
            params,
            str(response.url),
            headers,
            allowed_tags
        )
        html_with_base = html if params.no_base else f'<base href="{final_url}">{html}'
        parts = make_chunks_with_prefix(encode_sms_data(html_with_base))
        if len(parts) > SMS_LIMIT_PER_REQUEST and not params.no_limit:
            return await send_multipart_sms(number, encode_sms_data(f"Reached limit: {len(parts)} SMS"))
        await send_multipart_sms(number, parts)
    except httpx.TimeoutException:
        await send_multipart_sms(number, encode_sms_data("Request timeout"))
    except httpx.HTTPError as e:
        await send_multipart_sms(number, encode_sms_data(f"HTTP error: {e}"))
    except Exception as e:
        logger.error(f"Unexpected error processing request: {e}")
        await send_multipart_sms(number, encode_sms_data("Server error"))


async def main():
    load_host_mapping()
    logger.info("SMS server started")
    async for number, ctx, content in listen_sms():
        try:
            decoded_request = decode_sms_data(content)
            await process_request(number, decoded_request)
        except Exception as e:
            logger.exception("Exception while handling SMS from %s: %s", number, e)


if __name__ == '__main__':
    asyncio.run(main())
