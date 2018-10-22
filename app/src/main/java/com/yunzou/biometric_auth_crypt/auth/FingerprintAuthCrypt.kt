package com.yunzou.biometric_auth_crypt.auth

import android.annotation.SuppressLint
import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import androidx.core.hardware.fingerprint.FingerprintManagerCompat
import androidx.core.os.CancellationSignal
import java.security.*
import javax.crypto.Cipher

private const val KEY_STORE_NAME = "AndroidKeyStore"
private const val CRYPT_KEY_ALIAS = "biometric_crypt_key"

@RequiresApi(Build.VERSION_CODES.M)
private const val CRYPT_ALGORITHM = KeyProperties.KEY_ALGORITHM_RSA
@RequiresApi(Build.VERSION_CODES.M)
private const val CRYPT_PADDING = KeyProperties.ENCRYPTION_PADDING_RSA_OAEP
@RequiresApi(Build.VERSION_CODES.M)
private val CRYPT_MODE = KeyProperties.BLOCK_MODE_ECB
@RequiresApi(Build.VERSION_CODES.M)
private val TRANSFORMATION = "$CRYPT_ALGORITHM/$CRYPT_MODE/$CRYPT_PADDING"

class FingerprintAuthCrypt(val context: Context) : BiometricAuthCrypt {
    private val fingerprintManager: FingerprintManagerCompat
    private var cancellationSignal: CancellationSignal? = null

    init {
        try {
            fingerprintManager = FingerprintManagerCompat.from(context)
        } catch (e: Exception) {
            throw RuntimeException("Fail to init FingerprintManagerCompat")
        }
    }


    override fun encrypt(needEncrypt: ByteArray): ByteArray {
        return encrypt {
            it.doFinal(needEncrypt)
        }
    }

    override fun encrypt(fn: (cipher: Cipher) -> ByteArray): ByteArray {
        val cipher = createCryptCipher()
        return fn(cipher)
    }

    override fun decrypt(needDecrypt: ByteArray, callback: BiometricAuthCrypt.DecryptAuthCallback) {
        decrypt(callback) {
            it.doFinal(needDecrypt)
        }
    }

    override fun decrypt(
        callback: BiometricAuthCrypt.DecryptAuthCallback,
        decryptFn: (cipher: Cipher) -> ByteArray
    ) {
        cancellationSignal = CancellationSignal()
        fingerprintManager.authenticate(
            createDecryptCryptoObject(),
            0,
            cancellationSignal,
            object : FingerprintManagerCompat.AuthenticationCallback() {
                override fun onAuthenticationError(errMsgId: Int, errString: CharSequence?) {
                    // errMsgId == 5 时, 为用户主动取消
                    if (errMsgId == 5){
                        return
                    }
                    callback.onAuthenticationError(errMsgId, errString)
                }

                override fun onAuthenticationSucceeded(result: FingerprintManagerCompat.AuthenticationResult) {
                    try {
                        val cipher = result.cryptoObject.cipher!!
                        val decryptedData = decryptFn(cipher)
                        callback.onAuthenticationSucceeded(decryptedData)
                    } catch (e: Exception) {
                        callback.onAuthenticationFailed()
                    }
                }

                override fun onAuthenticationHelp(helpMsgId: Int, helpString: CharSequence?) {
                    callback.onAuthenticationHelp(helpMsgId, helpString)
                }

                override fun onAuthenticationFailed() {
                    callback.onAuthenticationFailed()
                }
            },
            null
        )
    }

    fun cancel() {
        cancellationSignal?.cancel()
    }

    fun cleanKey(){
        val keyStore = getKeyStore()
        keyStore.deleteEntry(CRYPT_KEY_ALIAS)
    }


    private fun createDecryptCryptoObject(): FingerprintManagerCompat.CryptoObject {
        val cipher = createCryptCipher(false)
        return FingerprintManagerCompat.CryptoObject(cipher)
    }

    @SuppressLint("NewApi")
    private fun createCryptCipher(isEncryptMode: Boolean = true): Cipher {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        if (isEncryptMode) {
            cipher.init(Cipher.ENCRYPT_MODE, getPublicKey())
        } else {
            cipher.init(Cipher.DECRYPT_MODE, getPrivateKey())
        }
        return cipher
    }

    private fun getKeyStore(): KeyStore {
        val keyStore = KeyStore.getInstance(KEY_STORE_NAME)
        keyStore.load(null)
        return keyStore
    }

    @RequiresApi(Build.VERSION_CODES.M)
    private fun getPrivateKey(): PrivateKey {
        try {
            val keyStore = getKeyStore()
            var key = keyStore.getKey(CRYPT_KEY_ALIAS, null) as PrivateKey
            if (key == null) {
                val keyPair = generateKey()
                key = keyPair.private
            }
            return key
        } catch (e: Exception) {
            throw java.lang.RuntimeException("Fail to get private key")
        }
    }

    @RequiresApi(Build.VERSION_CODES.M)
    private fun getPublicKey(): PublicKey {
        try {
            val keyStore = getKeyStore()
            var key = keyStore.getCertificate(CRYPT_KEY_ALIAS)?.publicKey
            if (key == null) {
                generateKey()
                key = keyStore.getCertificate(CRYPT_KEY_ALIAS).publicKey
            }
            return key!!
        } catch (e: Exception) {
            throw java.lang.RuntimeException("Fail to get public key")
        }
    }

    @RequiresApi(Build.VERSION_CODES.M)
    private fun generateKey(): KeyPair {
        val builder =
            KeyGenParameterSpec.Builder(CRYPT_KEY_ALIAS, KeyProperties.PURPOSE_DECRYPT or KeyProperties.PURPOSE_ENCRYPT)
                .setUserAuthenticationRequired(true)
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA1)
                .setBlockModes(CRYPT_MODE)
                .setEncryptionPaddings(CRYPT_PADDING)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            builder.setInvalidatedByBiometricEnrollment(false)
        }

        val keyPairGenerator = KeyPairGenerator.getInstance(CRYPT_ALGORITHM, KEY_STORE_NAME)
        keyPairGenerator.initialize(builder.build())
        return keyPairGenerator.genKeyPair()
    }

}