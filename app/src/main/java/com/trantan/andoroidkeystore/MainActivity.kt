package com.trantan.andoroidkeystore

import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import kotlinx.android.synthetic.main.activity_main.*
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.interfaces.RSAPublicKey
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream
import javax.security.auth.x500.X500Principal

class MainActivity : AppCompatActivity() {
    lateinit var keyStore: KeyStore
    lateinit var keyPair: KeyPair
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        initKeyStore()
        buttonGenerateKey.setOnClickListener {
            val alias = editAlias.text.toString()
            createKey(alias)
            getKeyInfo(alias)
        }
        buttonEncrypt.setOnClickListener {
            val alias = editAlias.text.toString()
            val clearText = editClearText.text.toString()
            if (clearText.isNotBlank() && alias.isNotBlank()) {
                encryptString(clearText, alias)
            }
        }
        buttonDecrypt.setOnClickListener {
            val alias = editAlias.text.toString()
            val cipherText = textEncrypt.text.toString()
            if (cipherText.isNotBlank() && alias.isNotBlank()) {
                decryptString(cipherText, alias)
            }
        }
        buttonGetAliases.setOnClickListener {
            getAliases()
        }
    }

    private fun initKeyStore() {
        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
        } catch (e: Exception) {
            Log.d(TAG, e.message.toString())
        }
    }

    private fun createKey(alias: String) {
        try {
            if (!keyStore.containsAlias(alias)) {
                val keyPairGenerator =
                    KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore")
                val parameterSpec = KeyGenParameterSpec.Builder(
                        alias,
                        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                    )
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                    .setDigests(KeyProperties.DIGEST_SHA1)
                    .build()
                keyPairGenerator.initialize(parameterSpec)
                keyPair = keyPairGenerator.genKeyPair()
            } else Toast.makeText(this, "Alias exist!!", Toast.LENGTH_SHORT).show()
        } catch (e: Exception) {
            Log.d(TAG, e.message.toString())
        }
    }

    private fun getKeyInfo(alias: String) {
        val privateKey: PrivateKey =
            (keyStore.getEntry(alias, null) as KeyStore.PrivateKeyEntry).privateKey
        val cert = keyStore.getCertificate(alias)
        val publicKey = cert.publicKey

        val publicKeyBytes: ByteArray = Base64.encode(publicKey.encoded, Base64.DEFAULT)
        val pubKeyString = String(publicKeyBytes)

//        val privateKeyBytes: ByteArray = Base64.encode(privateKey.encoded, Base64.DEFAULT)
//        val priKeyString = String(privateKeyBytes)
        Log.d(TAG, "------------>${pubKeyString} --- $")
        val keyInfo = "PublicKey: $pubKeyString"
        textKeyInfo.text = keyInfo

    }

    private fun encryptString(clearText: String, alias: String) {
        val publicKey = keyStore.getCertificate(alias).publicKey
        val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)
        val cipherText = cipher.doFinal(clearText.toByteArray(Charsets.UTF_8))

        textEncrypt.text = Base64.encodeToString(cipherText, Base64.DEFAULT)
    }

    private fun decryptString(cipherText: String, alias: String) {
        val privateKeyEntry = keyStore.getEntry(alias, null) as KeyStore.PrivateKeyEntry
        val privateKey = privateKeyEntry.privateKey
        val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cipher.init(Cipher.DECRYPT_MODE, privateKey)
        val decryptText = cipher.doFinal(Base64.decode(cipherText, Base64.DEFAULT))

        textDecrypt.text = String(decryptText)
    }

    private fun getAliases() {
        var aliasesString = ""
        val aliases = keyStore.aliases()
        while (aliases.hasMoreElements()) {
            aliasesString += "${aliases.nextElement()}, "
        }
        textAliases.text = aliasesString
    }


    private fun deleteKey(alias: String) {
        keyStore.deleteEntry(alias)
    }

    companion object {
        const val TAG = "MainActivity"
    }
}
