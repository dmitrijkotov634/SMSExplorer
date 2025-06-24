package com.wavecat.textbrowser

import java.math.BigInteger

object Base114 {
    private val SYMBOL_TABLE = arrayOf(
        "@",
        "£",
        "$",
        "¥",
        "è",
        "é",
        "ù",
        "ì",
        "ò",
        "Ç",
        "\n",
        "Ø",
        "ø",
        "Å",
        "å",
        "_",
        "Æ",
        "æ",
        "ß",
        "É",
        "!",
        "\"",
        "#",
        "¤",
        "%",
        "&",
        "'",
        "(",
        ")",
        "*",
        "+",
        ",",
        "-",
        ".",
        "/",
        "0",
        "1",
        "2",
        "3",
        "4",
        "5",
        "6",
        "7",
        "8",
        "9",
        ":",
        ";",
        "<",
        "=",
        ">",
        "?",
        "¡",
        "A",
        "B",
        "C",
        "D",
        "E",
        "F",
        "G",
        "H",
        "I",
        "J",
        "K",
        "L",
        "M",
        "N",
        "O",
        "P",
        "Q",
        "R",
        "S",
        "T",
        "U",
        "V",
        "W",
        "X",
        "Y",
        "Z",
        "Ä",
        "Ö",
        "Ñ",
        "Ü",
        "§",
        "¿",
        "a",
        "b",
        "c",
        "d",
        "e",
        "f",
        "g",
        "h",
        "i",
        "j",
        "k",
        "l",
        "m",
        "n",
        "o",
        "p",
        "q",
        "r",
        "s",
        "t",
        "u",
        "v",
        "w",
        "x",
        "y",
        "z",
        "ä",
        "ö",
        "ñ",
        "ü",
        "à"
    )

    private val SYMBOL_TO_VALUE = SYMBOL_TABLE.mapIndexed { index, symbol -> symbol to index }.toMap()

    fun encode(data: ByteArray): String {
        if (data.isEmpty()) return ""

        var num = BigInteger(1, data)
        val result = mutableListOf<String>()
        val base = BigInteger.valueOf(114)

        while (num > BigInteger.ZERO) {
            val remainder = num.remainder(base).toInt()
            result.add(SYMBOL_TABLE[remainder])
            num = num.divide(base)
        }

        return result.reversed().joinToString("")
    }

    fun decode(encoded: String): ByteArray {
        if (encoded.isEmpty()) return byteArrayOf()

        var num = BigInteger.ZERO
        val base = BigInteger.valueOf(114)

        for (char in encoded) {
            val value = SYMBOL_TO_VALUE[char.toString()]
                ?: throw IllegalArgumentException("Invalid character: $char")
            num = num.multiply(base).add(BigInteger.valueOf(value.toLong()))
        }

        return if (num == BigInteger.ZERO) {
            byteArrayOf(0)
        } else {
            num.toByteArray().let { bytes ->
                if (bytes[0] == 0.toByte() && bytes.size > 1) {
                    bytes.sliceArray(1 until bytes.size)
                } else {
                    bytes
                }
            }
        }
    }
}