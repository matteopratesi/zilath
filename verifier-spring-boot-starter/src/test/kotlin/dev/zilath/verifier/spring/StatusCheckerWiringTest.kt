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
import dev.zilath.verifier.core.CredentialStatus
import dev.zilath.verifier.core.OAuthStatusListChecker
import dev.zilath.verifier.core.StatusChecker
import dev.zilath.verifier.core.StatusListFetcher
import dev.zilath.verifier.core.TrustDecision
import dev.zilath.verifier.core.TrustEvaluator
import dev.zilath.verifier.openid4vp.VerificationFlow
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

/**
 * Revocation checking from the starter. It used to build no status checker at all, and the
 * only examples in the repository answered VALID to everything: the shortest way to a working
 * application switched revocation off.
 */
class StatusCheckerWiringTest {
    private val signingKey = ECKeyGenerator(Curve.P_256).keyID("rp-sign").generate()

    @Configuration(proxyBeanMethods = false)
    class TrustOnly {
        @Bean
        fun trustEvaluator(): TrustEvaluator = TrustEvaluator { TrustDecision.Untrusted("wiring test") }
    }

    @Configuration(proxyBeanMethods = false)
    class StatusListFetcherBean {
        @Bean
        fun statusListFetcher(): StatusListFetcher = StatusListFetcher { error("not fetched in this test") }
    }

    @Configuration(proxyBeanMethods = false)
    class OwnStatusChecker {
        @Bean
        fun statusChecker(): StatusChecker = StatusChecker { _, _ -> CredentialStatus.UNKNOWN }
    }

    @Test
    fun `a status list fetcher is enough, the starter builds the checker and the flow on it`() {
        starterRunnerWith(signingKey, TrustOnly::class.java, StatusListFetcherBean::class.java).run { context ->
            assertThat(context).hasNotFailed()
            assertThat(context.getBean(StatusChecker::class.java)).isInstanceOf(OAuthStatusListChecker::class.java)
            assertThat(context).hasSingleBean(VerificationFlow::class.java)
        }
    }

    @Test
    fun `without a status checker or a fetcher there is no flow`() {
        starterRunnerWith(signingKey, TrustOnly::class.java).run { context ->
            assertThat(context).hasNotFailed()
            assertThat(context).doesNotHaveBean(StatusChecker::class.java)
            assertThat(context).doesNotHaveBean(VerificationFlow::class.java)
        }
    }

    @Test
    fun `the application's own status checker is kept beside a fetcher`() {
        starterRunnerWith(
            signingKey,
            TrustOnly::class.java,
            StatusListFetcherBean::class.java,
            OwnStatusChecker::class.java,
        ).run { context ->
            assertThat(context).hasSingleBean(StatusChecker::class.java)
            assertThat(context.getBean(StatusChecker::class.java)).isNotInstanceOf(OAuthStatusListChecker::class.java)
            assertThat(context).hasSingleBean(VerificationFlow::class.java)
        }
    }
}
