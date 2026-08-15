package org.noticer.collector

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import java.security.KeyPairGenerator
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class AttestationEvidence(
    val certificateChainDer: List<ByteArray>,
) : AutoCloseable {
    override fun close() {
        certificateChainDer.forEach { it.fill(0) }
    }
}

interface KeyAttester {
    fun attest(challenge: ByteArray): AttestationEvidence
}

class AndroidKeyAttester(
    private val alias: String = "noticer-collector-attestation",
) : KeyAttester {
    override fun attest(challenge: ByteArray): AttestationEvidence {
        require(challenge.size in 16..128) { "Attestation challenge length is invalid" }
        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        generator.initialize(
            KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge(challenge.copyOf())
                .build(),
        )
        generator.generateKeyPair()
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val chain = requireNotNull(keyStore.getCertificateChain(alias))
            .map { certificate -> certificate.encoded.copyOf() }
        return AttestationEvidence(chain)
    }
}

class BaselineMaterial(private val bytes: ByteArray) : AutoCloseable {
    fun useBytes(block: (ByteArray) -> Unit) = block(bytes)

    override fun close() {
        bytes.fill(0)
    }
}

class PrivateBaselineStore(context: Context) {
    private val file = AtomicFile(context.filesDir.resolve("private-baseline.aesgcm"))
    private val alias = "noticer-private-baseline"

    fun save(plaintext: ByteArray) {
        require(plaintext.isNotEmpty()) { "Baseline must not be empty" }
        val working = plaintext.copyOf()
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
            val encrypted = cipher.doFinal(working)
            val output = file.startWrite()
            try {
                output.write(cipher.iv.size)
                output.write(cipher.iv)
                output.write(encrypted)
                file.finishWrite(output)
            } catch (error: Throwable) {
                file.failWrite(output)
                throw error
            } finally {
                encrypted.fill(0)
            }
        } finally {
            working.fill(0)
        }
    }

    fun load(): BaselineMaterial {
        val payload = file.readFully()
        require(payload.isNotEmpty()) { "Encrypted baseline is empty" }
        val ivLength = payload[0].toInt() and 0xff
        require(ivLength in 12..16 && payload.size > ivLength + 1) { "Encrypted baseline is malformed" }
        val iv = payload.copyOfRange(1, 1 + ivLength)
        val ciphertext = payload.copyOfRange(1 + ivLength, payload.size)
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(), GCMParameterSpec(128, iv))
            BaselineMaterial(cipher.doFinal(ciphertext))
        } finally {
            payload.fill(0)
            iv.fill(0)
            ciphertext.fill(0)
        }
    }

    fun delete() = file.delete()

    private fun getOrCreateKey(): SecretKey {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (keyStore.getKey(alias, null) as? SecretKey)?.let { return it }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").run {
            init(
                KeyGenParameterSpec.Builder(
                    alias,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .build(),
            )
            generateKey()
        }
    }
}

