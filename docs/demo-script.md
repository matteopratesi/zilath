# Scaletta video demo (90 secondi)

> Da registrare (Matteo). Setup CONSIGLIATO: modalità **CED simulata** (README, "Simulated
> CED mode") — il biglietto si sblocca per il DIRITTO, non per l'identità. Dire sempre
> "simulata": la CED reale è già su app IO, ma le venue private non possono ancora
> verificarla in produzione (accreditamento RP atteso nel 2027). Terminale pronto col
> comando run-ced-wallet.sh, browser su http://localhost:8080/demo.

| Tempo | Scena | Voce (indicativa) |
|---|---|---|
| 0-10s | Pagina evento del "Teatro di Prova", biglietto a €35 | "Oggi, per avere il biglietto accompagnatore, una persona con disabilità manda il proprio verbale INPS via email. A ogni evento, da capo." |
| 10-20s | Click su "Ho diritto al biglietto accompagnatore" → appare il QR | "Con Varco basta il wallet: la pagina chiede una credenziale, non un documento." |
| 20-40s | Terminale: il wallet di test presenta la CED SIMULATA (comando già pronto) | "Il wallet presenta la Carta della Disabilità — qui simulata: quella vera è già nel wallet dello Stato, ma i verificatori privati saranno accreditati solo nel 2027. Stessi nomi di claim della credenziale reale. Cifrata, firmata, legata a questa transazione: non si può copiare né riusare." |
| 40-55s | La pagina passa al biglietto verde: "Diritto al biglietto accompagnatore verificato" | "Il sistema sa una cosa sola: che il diritto c'è. Non la diagnosi, non la percentuale, non la storia clinica. Ed ecco il biglietto, intestato." |
| 55-75s | Click su "Ricevuta di verifica firmata": mostrare il JWT decodificato (jwt.io o simile) | "Questo è tutto ciò che il teatro conserva: esito, orario, transazione. Niente diagnosi, niente verbale, niente dati sanitari. La ricevuta è firmata: vale come prova." |
| 75-90s | Ritorno alla pagina evento | "Verifichi una volta, compri ovunque come tutti. Il codice è open source: la fiducia si ispeziona. Questo è Varco." |

Note di regia:
- Tenere visibili insieme browser (sx) e terminale (dx). Il wallet della demo CED è il
  simulatore incluso nel repo (run-ced-wallet.sh); in modalità PID è invece il conformance
  tool ufficiale PagoPA — dirlo rafforza la credibilità.
- Il nome sul biglietto è quello della credenziale simulata (Maria Bianchi): farlo notare.
- La parola "simulata" va detta esplicitamente: è onestà, e spiega il calendario 2027.
- Nessun dato reale in scena.
