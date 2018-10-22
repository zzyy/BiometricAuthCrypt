package com.yunzou.biometric_auth_crypt

import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.yunzou.biometric_auth_crypt.auth.BiometricAuthCrypt
import com.yunzou.biometric_auth_crypt.auth.FingerprintAuthCrypt

class MainActivity : AppCompatActivity() {
    private val TAG = "AppCompatActivity"
    lateinit var fingerprintAuthHelper: FingerprintAuthCrypt
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        fingerprintAuthHelper = FingerprintAuthCrypt(this)
    }

    var encryptData: ByteArray? = null

    fun encrypt(v: View) {
        encryptData = fingerprintAuthHelper.encrypt("aaaa".toByteArray())
        Toast.makeText(this, "encrypt success", Toast.LENGTH_SHORT).show()
    }

    fun decrypt(v: View) {
        fingerprintAuthHelper.decrypt(encryptData!!, object : BiometricAuthCrypt.DecryptAuthCallback {
            override fun onAuthenticationSucceeded(decrytData: ByteArray) {
                super.onAuthenticationSucceeded(decrytData)
                Toast.makeText(this@MainActivity, String(decrytData), Toast.LENGTH_SHORT).show()
            }

            override fun onAuthenticationError(errMsgId: Int, errString: CharSequence?) {
                super.onAuthenticationError(errMsgId, errString)
                Log.w(TAG, "$errString")
                Toast.makeText(this@MainActivity, "onAuthenticationError $errString  $errMsgId", Toast.LENGTH_SHORT).show()
            }

            override fun onAuthenticationHelp(helpMsgId: Int, helpString: CharSequence?) {
                super.onAuthenticationHelp(helpMsgId, helpString)
                Toast.makeText(this@MainActivity, "onAuthenticationHelp $helpString", Toast.LENGTH_SHORT).show()
                Log.w(TAG, "$helpString")
            }

            override fun onAuthenticationFailed() {
                super.onAuthenticationFailed()
                Toast.makeText(this@MainActivity, "onAuthenticationFailed", Toast.LENGTH_SHORT).show()
            }
        })
    }

    fun cancel(v:View){
        fingerprintAuthHelper.cancel()
    }
}
