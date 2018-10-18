package com.yunzou.biometric_auth_crypt.auth

import javax.crypto.Cipher

interface BiometricAuthCrypt {
    interface DecryptAuthCallback {
        fun onAuthenticationError(errMsgId: Int, errString: CharSequence?) {
        }

        fun onAuthenticationSucceeded(decrytData: ByteArray) {
        }

        fun onAuthenticationHelp(helpMsgId: Int, helpString: CharSequence?) {
        }

        fun onAuthenticationFailed() {
        }
    }

    fun encrypt(needEncrypt: ByteArray): ByteArray
    fun encrypt(fn: (cipher: Cipher) -> ByteArray): ByteArray
    fun decrypt(needDecrypt: ByteArray, callback: BiometricAuthCrypt.DecryptAuthCallback)

    fun decrypt(callback: BiometricAuthCrypt.DecryptAuthCallback, decryptFn: (cipher: Cipher) -> ByteArray)

}