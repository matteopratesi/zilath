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
package dev.zilath.gate

/*
 * Server-rendered pages of the gate flow. Italian copy: the audience is the venue
 * operator at the door. Deliberately boring HTML: no build step, self-hostable as-is.
 */

/** Escapes operator-provided values before interpolating them into HTML. */
internal fun escape(value: String): String =
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
        main { max-width: 42rem; margin: 2rem auto; padding: 2rem; background: #fff; border-radius: 12px;
               box-shadow: 0 2px 12px rgba(0,0,0,.08); }
        h1 { font-size: 1.4rem; } .muted { color: #666; }
        .btn { display: inline-block; padding: .8rem 1.4rem; background: #14532d; color: #fff; border: 0;
               border-radius: 8px; text-decoration: none; font-weight: 600; font-size: 1rem; cursor: pointer; }
        .btn.no { background: #7f1d1d; }
        .ok { color: #14532d; font-weight: 700; } .no { color: #7f1d1d; font-weight: 700; }
        ol li { margin: .6rem 0; }
        .warn { background: #fef3c7; border-radius: 8px; padding: .8rem 1rem; }
        label { display: block; margin-top: 1rem; font-weight: 600; }
        input, select { font-size: 1rem; padding: .5rem; margin-top: .3rem; width: 100%; box-sizing: border-box; }
        textarea.jws { width: 100%; height: 7rem; font-family: monospace; font-size: .75rem; }
        table { width: 100%; border-collapse: collapse; } td, th { padding: .4rem; border-bottom: 1px solid #eee;
               text-align: left; }
      </style>
    </head>
    <body><main>$body</main></body>
    </html>
    """.trimIndent()

internal fun homeHtml(
    venue: String,
    todayCount: Int,
): String =
    page(
        "Verifica al varco",
        """
        <p class="muted">${escape(venue)} — verifica al varco</p>
        <h1>Verifica dei diritti all'ingresso</h1>
        <p>La persona esibisce la Carta Europea della Disabilità, tu la verifichi sul
        servizio INPS e qui registri <strong>solo l'esito</strong>. Mai documenti,
        mai copie, mai dati della persona.</p>
        <p><a class="btn" href="/gate/new">Nuova verifica</a></p>
        <p class="muted">Oggi: $todayCount verifiche registrate — <a href="/gate/today">vedi l'elenco</a></p>
        """.trimIndent(),
    )

internal fun newVerificationHtml(
    venue: String,
    entitlements: List<String>,
): String {
    val options = entitlements.joinToString("") { "<option>${escape(it)}</option>" }
    return page(
        "Nuova verifica",
        """
        <p class="muted">${escape(venue)} — verifica al varco</p>
        <h1>Segui i passi, poi registra l'esito</h1>
        <ol>
          <li><strong>Fatti esibire la Carta Europea della Disabilità</strong> (fisica o
              digitale su app IO) insieme a un documento d'identità.</li>
          <li><strong>Inquadra il QR sul retro della carta col tuo telefono</strong>:
              si apre il servizio INPS. Inserisci il codice fiscale che ti detta
              l'interessato e premi Verifica. L'esito atteso è <em>"Carta Valida"</em>.</li>
          <li>Se l'agevolazione riguarda l'accompagnatore, <strong>controlla la lettera
              "A"</strong> stampata sul fronte della carta.</li>
        </ol>
        <p class="warn">Non trascrivere <strong>mai</strong> nome, codice fiscale o numero
        della carta: la ricevuta registra soltanto esito, ora e operatore. Se il diritto
        non risulta, si applica la tariffa ordinaria: nessun altro dato serve.</p>
        <form method="post" action="/gate/record">
          <label>Agevolazione richiesta
            <select name="entitlement">$options</select>
          </label>
          <label>Operatore (sigla o nome di servizio)
            <input name="operator" maxlength="40" required placeholder="es. MP">
          </label>
          <p>
            <button class="btn" name="outcome" value="verified">Diritto verificato</button>
            <button class="btn no" name="outcome" value="not-verified">Diritto non verificato</button>
          </p>
        </form>
        <p><a href="/gate">← Annulla</a></p>
        """.trimIndent(),
    )
}

internal fun receiptHtml(
    venue: String,
    receipt: GateReceipts.Receipt,
): String {
    val verified = receipt.outcome == GateReceipts.OUTCOME_VERIFIED
    val headline =
        if (verified) {
            """<p class="ok">✔ Diritto verificato</p>"""
        } else {
            """<p class="no">✘ Diritto non verificato</p>"""
        }
    return page(
        "Ricevuta di verifica",
        """
        <p class="muted">${escape(venue)} — verifica al varco</p>
        $headline
        <p>${escape(receipt.entitlement)} — operatore ${escape(receipt.operator)}<br>
        <span class="muted">${receipt.issuedAt}</span></p>
        <p class="muted">Questa ricevuta firmata è l'<strong>unica</strong> cosa che la
        struttura conserva: prova che la verifica è avvenuta e come è andata — mai chi era
        la persona.</p>
        <textarea class="jws" readonly>${escape(receipt.jws)}</textarea>
        <p><a class="btn" href="/gate/new">Nuova verifica</a> <a href="/gate/today">Elenco di oggi</a></p>
        """.trimIndent(),
    )
}

internal fun todayHtml(
    venue: String,
    receipts: List<GateReceipts.Receipt>,
): String {
    val rows =
        receipts.joinToString("") { r ->
            val outcome = if (r.outcome == GateReceipts.OUTCOME_VERIFIED) "✔" else "✘"
            """<tr><td>${r.issuedAt}</td><td>${escape(r.entitlement)}</td>""" +
                """<td>$outcome</td><td>${escape(r.operator)}</td>""" +
                """<td><a href="/gate/receipt/${escape(r.id)}">ricevuta</a></td></tr>"""
        }
    return page(
        "Verifiche di oggi",
        """
        <p class="muted">${escape(venue)} — verifica al varco</p>
        <h1>Verifiche di oggi (${receipts.size})</h1>
        <table>
          <tr><th>Ora</th><th>Agevolazione</th><th>Esito</th><th>Operatore</th><th></th></tr>
          $rows
        </table>
        <p><a class="btn" href="/gate/new">Nuova verifica</a> <a href="/gate">← Home</a></p>
        """.trimIndent(),
    )
}

internal fun notFoundGateHtml(): String =
    page(
        "Ricevuta sconosciuta",
        """
        <h1>Ricevuta sconosciuta</h1>
        <p><a class="btn" href="/gate">Torna alla home</a></p>
        """.trimIndent(),
    )
