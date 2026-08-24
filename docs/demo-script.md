# Scaletta video demo (90 secondi)

> Da registrare (Matteo). Setup: app avviata come da README "Try the demo", terminale
> pronto col comando del wallet di test, browser su http://localhost:8080/demo.

| Tempo | Scena | Voce (indicativa) |
|---|---|---|
| 0-10s | Pagina evento del "Teatro di Prova", biglietto a €35 | "Oggi, per avere il biglietto accompagnatore, una persona con disabilità manda il proprio verbale INPS via email. A ogni evento, da capo." |
| 10-20s | Click su "Ho diritto al biglietto accompagnatore" → appare il QR | "Con Varco basta il wallet: la pagina chiede una credenziale, non un documento." |
| 20-40s | Terminale: parte il wallet di test che presenta il PID (comando già pronto) | "Il wallet presenta la credenziale dello Stato. Cifrata, firmata, legata a questa transazione: non si può copiare né riusare." |
| 40-55s | La pagina passa da 'in attesa' al biglietto verde NOMINATIVO | "Il sistema risponde solo sì o no. Ed ecco il biglietto accompagnatore, intestato." |
| 55-75s | Click su "Ricevuta di verifica firmata": mostrare il JWT decodificato (jwt.io o simile) | "Questo è tutto ciò che il teatro conserva: esito, orario, transazione. Niente diagnosi, niente verbale, niente dati sanitari. La ricevuta è firmata: vale come prova." |
| 75-90s | Ritorno alla pagina evento | "Verifichi una volta, compri ovunque come tutti. Il codice è open source: la fiducia si ispeziona. Questo è Varco." |

Note di regia:
- Tenere visibili insieme browser (sx) e terminale (dx): il "wallet" della demo è il
  conformance tool ufficiale PagoPA, e dirlo rafforza la credibilità.
- Il nome sul biglietto è quello del PID di test (Ada Lovelace o simile): farlo notare.
- Nessun dato reale in scena.
