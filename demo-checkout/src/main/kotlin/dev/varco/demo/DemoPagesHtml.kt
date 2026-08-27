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
package dev.varco.demo

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive

/*
 * Server-rendered pages of the demo (plan: simple server-side templates, no SPA).
 * Italian copy: the demo's audience is Italian venues and associations.
 */

/** Escapes a value coming from credential claims before interpolating it into HTML. */
internal fun htmlEscape(value: String): String =
    value
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\"", "&quot;")
        .replace("'", "&#39;")

private fun page(
    title: String,
    body: String,
): String =
    """
    <!doctype html>
    <html lang="it">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>$title</title>
      <style>
        body { font-family: -apple-system, system-ui, sans-serif; margin: 0; background: #f4f1ea; color: #1c1c1c; }
        main { max-width: 42rem; margin: 3rem auto; padding: 2rem; background: #fff; border-radius: 12px;
               box-shadow: 0 2px 12px rgba(0,0,0,.08); }
        h1 { font-size: 1.5rem; } .muted { color: #666; }
        .btn { display: inline-block; padding: .8rem 1.4rem; background: #14532d; color: #fff;
               border-radius: 8px; text-decoration: none; font-weight: 600; }
        .ticket { border: 2px dashed #14532d; border-radius: 12px; padding: 1.5rem; margin-top: 1rem; }
        .ok { color: #14532d; font-weight: 700; }
        code { background: #f0f0f0; padding: .15rem .4rem; border-radius: 4px; font-size: .85em; }
        img.qr { display: block; margin: 1rem auto; }
      </style>
    </head>
    <body><main>$body</main></body>
    </html>
    """.trimIndent()

internal fun eventPageHtml(): String =
    page(
        "Concerto — Teatro di Prova",
        """
        <p class="muted">DEMO — nessun dato reale</p>
        <h1>Concerto d'autunno — Teatro di Prova</h1>
        <p>Venerdì 20 novembre 2026, ore 21:00 — Platea, posto D12 — <strong>€ 35,00</strong></p>
        <hr>
        <p>Hai diritto al <strong>biglietto accompagnatore gratuito</strong>?</p>
        <p><a class="btn" href="/demo/entitled">Ho diritto al biglietto accompagnatore</a></p>
        <p class="muted">Sei già sul telefono con il wallet?
        <a href="/demo/entitled?flow=same-device">Prosegui su questo dispositivo</a>.</p>
        <p class="muted">La verifica avviene con la credenziale del tuo wallet: al teatro arriva solo
        un sì/no firmato. Nessun documento viene inviato, mostrato o conservato.</p>
        """.trimIndent(),
    )

internal fun waitPageHtml(
    txId: String,
    qrPayload: String,
    walletCommand: String = "./scripts/run-demo-wallet.sh $txId",
): String =
    page(
        "Verifica in corso",
        """
        <h1>Inquadra il QR col tuo wallet</h1>
        <img class="qr" src="/demo/qr/$txId.png" width="320" height="320" alt="QR OpenID4VP">
        <p class="muted">Oppure, per la demo, fai presentare la credenziale al wallet di test:<br>
        <code>$walletCommand</code></p>
        <p id="status" class="muted">In attesa della presentazione…</p>
        <details><summary class="muted">authorize URL</summary><p><code>$qrPayload</code></p></details>
        <script>
          const poll = setInterval(async () => {
            const r = await fetch('/demo/status/$txId');
            const s = (await r.json()).status;
            if (s === 'verified') { clearInterval(poll); location.href = '/demo/ticket/$txId'; }
            else if (s !== 'pending') {
              clearInterval(poll);
              document.getElementById('status').textContent = 'Verifica non riuscita (' + s + ').';
            }
          }, 2000);
        </script>
        """.trimIndent(),
    )

/** Renders the verified ticket from the disclosed claims. */
internal fun verifiedTicketHtml(
    txId: String,
    claims: JsonObject,
): String {
    val holder =
        listOfNotNull(
            claims["given_name"]?.jsonPrimitive?.content,
            claims["family_name"]?.jsonPrimitive?.content,
        ).joinToString(" ").ifBlank { "—" }
    val entitledLine =
        if (claims["constant_attendance_allowance"]?.jsonPrimitive?.content == "true") {
            "Diritto al biglietto accompagnatore verificato — credenziale CED SIMULATA"
        } else {
            null
        }
    return ticketHtml(txId, holder, entitledLine)
}

internal fun ticketHtml(
    txId: String,
    holder: String,
    entitledLine: String? = null,
): String =
    page(
        "Biglietto accompagnatore",
        """
        <p class="ok">✔ ${entitledLine ?: "Diritto verificato"}</p>
        <h1>Biglietto accompagnatore — omaggio</h1>
        <div class="ticket">
          <p><strong>Concerto d'autunno — Teatro di Prova</strong><br>
          Venerdì 20 novembre 2026, ore 21:00 — Platea, posto D13</p>
          <p>Intestato a: <strong>${htmlEscape(holder)}</strong><br>
          <span class="muted">Biglietto nominativo, valido solo insieme al titolare del diritto.</span></p>
          <p class="muted">Transazione: <code>$txId</code> — DEMO, non valido per l'ingresso</p>
        </div>
        <p><a href="/demo/receipt/$txId">Ricevuta di verifica firmata</a> —
        <span class="muted">l'unica cosa che il teatro conserva: esito e orario, mai i tuoi documenti.</span></p>
        <p><a href="/demo">← Torna all'evento</a></p>
        """.trimIndent(),
    )

internal fun notVerifiedHtml(txId: String): String =
    page(
        "Verifica non completata",
        """
        <h1>Verifica non completata</h1>
        <p class="muted">La transazione <code>$txId</code> non risulta verificata.</p>
        <p><a class="btn" href="/demo">Riprova dall'evento</a></p>
        """.trimIndent(),
    )

internal fun notEntitledHtml(txId: String): String =
    page(
        "Diritto non presente",
        """
        <h1>La credenziale è valida, ma il diritto non c'è</h1>
        <p class="muted">La carta presentata non include il diritto al biglietto accompagnatore
        o risulta scaduta. Transazione <code>$txId</code>.</p>
        <p><a class="btn" href="/demo">Torna all'evento</a></p>
        """.trimIndent(),
    )

internal fun notFoundHtml(): String =
    page(
        "Transazione sconosciuta",
        """
        <h1>Transazione sconosciuta</h1>
        <p><a class="btn" href="/demo">Torna all'evento</a></p>
        """.trimIndent(),
    )
