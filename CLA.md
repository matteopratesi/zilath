# Contributor License Agreement

By contributing to Zilath you agree to the terms below. They apply to every contribution
you send to this project — code, documentation, tests, examples.

This document is deliberately short and says plainly what it takes and what it gives. A
contributor agreement is an asymmetric instrument by nature: it asks you for permissions
the project does not give back. Section 4 is what this project offers to balance it, and
it is binding on the maintainer in the same way sections 2 and 3 are binding on you.

## 1. Why this exists

Zilath is released under the **AGPL-3.0**. Some organisations cannot use AGPL software —
typically because they embed it in a product they do not publish — and for those a
separate commercial licence is available for a fee. That is the project's only intended
source of revenue, and it exists so that the people this library was written for never
have to pay to exercise a right.

Offering that second licence requires permission from everyone who wrote part of the code.
Without an agreement like this one, a single contributor's code would make the whole work
impossible to licence any other way. That is the entire purpose of this document.

## 2. What you grant

You keep the copyright in what you write. You grant Matteo Pratesi (the "maintainer"):

- a perpetual, worldwide, non-exclusive, royalty-free, irrevocable **copyright licence**
  to reproduce, modify, publish and distribute your contribution and derivative works of
  it, **including under licence terms different from the AGPL-3.0**, subject to section 4;
- a perpetual, worldwide, non-exclusive, royalty-free, irrevocable **patent licence** to
  make, use, sell and otherwise transfer your contribution, covering only those patent
  claims you own or control that your contribution necessarily infringes, alone or in
  combination with the project.

The patent licence you grant terminates for anyone who starts patent litigation alleging
that the project or a contribution to it infringes a patent.

## 3. What you keep

You keep the copyright in your contribution, and every right to use it however you like
elsewhere. This agreement is a licence, not a transfer: you are not signing your work
away, and you are not giving up the right to publish the same code under any other terms,
in any other project.

## 4. What the project commits to in return

These commitments bind the maintainer and any successor who takes over the project:

1. **Every release of Zilath stays available under the AGPL-3.0**, or under another
   licence approved by the Open Source Initiative that grants at least the same freedoms.
   A commercial licence is only ever sold **in addition to** the open one, never as a
   replacement for it.
2. **No open-core.** The project will not hold back features, modules or fixes from the
   open version in order to sell them. What exists, exists for everyone.
3. **Verification will never be metered against the person being verified.** No feature
   of this library will be built to charge, count or profile the holder of a credential.
4. If the project is ever transferred, sold or discontinued, the code released up to that
   point **stays under the licence it was published with**. Nobody can retroactively close
   what has already been given.

If the maintainer breaks commitment 1 or 2, the permission you granted in section 2 to
licence your contribution under different terms ends for contributions you made before the
breach — the AGPL licence on your work, like everyone else's, continues unaffected.

## 5. What you are telling us

By contributing you confirm that:

- the contribution is your own work, or you have the right to submit it under this
  agreement;
- if your employer has rights in what you write, you have their permission to contribute,
  or they have waived those rights;
- to your knowledge, your contribution does not infringe anyone else's rights;
- any third-party material in your contribution is clearly identified, together with the
  licence it comes under.

You provide your contribution **as is**, without warranties of any kind. You are not
expected to support it.

## 6. How to sign

Add a `Signed-off-by` line to your commits:

```
git commit -s
```

which appends:

```
Signed-off-by: Your Name <your.email@example.com>
```

Using a name you can be reached at. That line means: *I have read `CLA.md` and I agree to
it for this contribution.* No separate form, no account, no scanned signature.

For a substantial contribution the maintainer may ask you to confirm the same thing by
email, so that the agreement is recorded somewhere other than the git history.

---

Questions about any of this are welcome before you write code, not after. If a clause is a
problem for you or your employer, open an issue and say so — it is easier to fix a document
than to unpick a contribution nobody can licence.
