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
package dev.zilath.verifier.trust

import dev.zilath.verifier.core.DocumentNotFoundException
import dev.zilath.verifier.core.HttpDocumentFetcher

/**
 * A [FederationFetcher] over [documents]: the network boundary of [HttpDocumentFetcher] —
 * the library's URL shape rule, hosts that resolve only to globally routable addresses and a
 * connection to those alone, no redirects, bounded time and size — with the server's 404 or
 * 410 passed on as [FederationDocumentNotFoundException], the federation's answer that it
 * does not publish the document. Every other failure, a refused destination among them,
 * counts as the federation not reached.
 */
class HttpFederationFetcher(
    private val documents: HttpDocumentFetcher = HttpDocumentFetcher(),
) : FederationFetcher {
    override fun fetch(url: String): String =
        try {
            documents.fetch(url)
        } catch (notFound: DocumentNotFoundException) {
            throw FederationDocumentNotFoundException(notFound.message, notFound)
        }
}
