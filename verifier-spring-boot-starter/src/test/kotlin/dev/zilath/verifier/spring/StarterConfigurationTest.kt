/*
 * Copyright (C) 2026 Matteo Pratesi
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package dev.zilath.verifier.spring

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import dev.zilath.verifier.core.DisclosedClaims
import dev.zilath.verifier.core.VerificationResult
import dev.zilath.verifier.openid4vp.DirectPostBody
import dev.zilath.verifier.openid4vp.FlowOutcome
import dev.zilath.verifier.openid4vp.InMemoryTransactionStore
import dev.zilath.verifier.openid4vp.PresentationRequest
import dev.zilath.verifier.openid4vp.StartedTransaction
import dev.zilath.verifier.openid4vp.TransactionStore
import dev.zilath.verifier.openid4vp.VerificationFlow
import kotlinx.serialization.json.JsonObject
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.time.Clock

/** What the starter builds from `zilath.openid4vp.*`, and what it refuses to start with. */
class StarterConfigurationTest {
    private val signingKey = ECKeyGenerator(Curve.P_256).keyID("rp-sign").generate()

    private val runner = starterRunner(signingKey)

    @Test
    fun `without a response encryption key each transaction encrypts to a key of its own`() {
        runner.run { context ->
            assertThat(context).hasNotFailed()
            val flow = context.getBean(VerificationFlow::class.java)
            val published = List(2) { publishedEncryptionKeyOf(requestObjectOf(flow, start(flow))) }
            assertThat(published.map { it.keyID }).doesNotHaveDuplicates()
            assertThat(published.map { it.computeThumbprint() }).doesNotHaveDuplicates()
        }
    }

    @Test
    fun `a configured response encryption key is the fallback a response may be encrypted to`() {
        val staticKey = ECKeyGenerator(Curve.P_256).keyID("rp-enc").generate()
        runner
            .withPropertyValues("zilath.openid4vp.response-encryption-key-jwk=${staticKey.toJSONString()}")
            .run { context ->
                context.getBean(ScriptedVerifier::class.java).next =
                    VerificationResult.Verified(DisclosedClaims(JsonObject(emptyMap())))
                val flow = context.getBean(VerificationFlow::class.java)
                val started = start(flow)
                val response = encryptedResponseFor(requestObjectOf(flow, started), encryptTo = staticKey.toPublicJWK())
                val outcome =
                    flow
                        .handleWalletResponse(
                            started.id,
                            DirectPostBody(mapOf("response" to response)),
                        ).outcome
                assertThat(outcome).isInstanceOf(FlowOutcome.Verified::class.java)
            }
    }

    @Test
    fun `the wallet response limit is the one configured`() {
        val oversized = DirectPostBody(mapOf("response" to "x".repeat(5_000)))
        runner.withPropertyValues("zilath.openid4vp.max-wallet-response-length=4096").run { context ->
            val flow = context.getBean(VerificationFlow::class.java)
            val started = start(flow)
            val outcome = flow.handleWalletResponse(started.id, oversized).outcome as FlowOutcome.Rejected
            assertThat(outcome.detail).isEqualTo("wallet response exceeds the size limit")
        }
        // The same body under the default limit goes on to be decoded.
        runner.run { context ->
            val flow = context.getBean(VerificationFlow::class.java)
            val started = start(flow)
            val outcome = flow.handleWalletResponse(started.id, oversized).outcome as FlowOutcome.Rejected
            assertThat(outcome.detail).isEqualTo("wallet response is not a JWE")
        }
    }

    @Test
    fun `a transaction store of the application's is the one the flow uses`() {
        InMemoryTransactionStore(Clock.systemUTC()).use { applicationStore ->
            runner.withBean(TransactionStore::class.java, { applicationStore }).run { context ->
                val started = start(context.getBean(VerificationFlow::class.java))
                assertThat(applicationStore.get(started.id)).isNotNull()
            }
        }
    }

    @Test
    fun `the flow is closed with its context, and the store it created with it`() {
        lateinit var flow: VerificationFlow
        lateinit var started: StartedTransaction
        runner.run { context ->
            flow = context.getBean(VerificationFlow::class.java)
            started = start(flow)
            assertThat(flow.requestJwtFor(started.id)).isNotNull()
        }
        // The context is closed: the in-memory store the flow owned holds nothing any more.
        assertThat(flow.requestJwtFor(started.id)).isNull()
    }

    private fun start(flow: VerificationFlow): StartedTransaction =
        flow.start(PresentationRequest.forTestPid("urn:zilath:test:entitlement"))

    private fun requestObjectOf(
        flow: VerificationFlow,
        started: StartedTransaction,
    ): String = checkNotNull(flow.requestJwtFor(started.id))
}
