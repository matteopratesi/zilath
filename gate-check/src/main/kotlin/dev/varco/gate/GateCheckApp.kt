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
package dev.varco.gate

import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.context.annotation.Bean
import java.nio.file.Path
import java.time.Clock

/**
 * Gate-check: the piece that helps TODAY (VARCO-40). A tiny web app the venue
 * self-hosts: the operator follows a guided flow, the person shows the European
 * Disability Card, the operator verifies its QR on the INPS service (exactly what the
 * State expects them to do), and the tool records ONLY the signed outcome.
 * Zero copies, zero PDFs in mailboxes; the venue stays the data controller it already was.
 */
@SpringBootApplication
class GateCheckApp {
    @Bean
    fun clock(): Clock = Clock.systemDefaultZone()

    @Bean
    fun gateReceipts(
        @Value("\${varco.gate.data-dir}") dataDir: String,
        @Value("\${varco.gate.venue-name}") venueName: String,
        clock: Clock,
    ): GateReceipts = GateReceipts(Path.of(dataDir), venueName, clock)
}

@Suppress("SpreadOperator") // canonical Spring Boot Kotlin entry point
fun main(args: Array<String>) {
    runApplication<GateCheckApp>(*args)
}
