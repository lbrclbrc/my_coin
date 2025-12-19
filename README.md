# my_coin (protocol & prototype)

- A cryptocurrency protocol and prototype that supports anonymous payments **without any backdoor**, while still allowing users to use their own private keys to unlock their own anonymous payment history and help recover stolen funds.

- **Where to start**
  - If you want a general idea of what my_coin does and what this prototype currently supports, read this **README**.
  - If you are already familiar with what zero-knowledge proofs and Zcash-style anonymity systems can do (no need to know their low-level internals) and want more protocol and prototype details, see **whitepaper_draft (md or pdf)** in the project root. 

---

## Summary

> An anonymous payment protocol **without backdoors** (my_coin protocol)  
> A single-node blockchain prototype built in Python with Rust ZK modules  
> Core idea: an anonymous payment system that gives honest users privacy while making theft, extortion, and money laundering a losing game.

- **What is this project?**
  - **my_coin protocol** is a cryptocurrency protocol design that aims to support anonymous payments *and* make it easy to trace responsibility afterwards. It is currently at a draft-spec stage.
  - **my_coin prototype** is a minimal working implementation (MVP) based on this protocol design, used to demonstrate and validate the core mechanisms.
  - This repo contains both the protocol draft for my_coin and the corresponding prototype implementation.

- **Core mechanism of the protocol (very roughly)**
  - Only accounts that have gone through real-name KYC and signed a user agreement are granted “anonymous payment permission” (you can think of these as **blue addresses**).
  - Anonymous payments still hide “who is paying whom” from third parties on chain, but the protocol guarantees: as long as the account holder is willing to use their own private key, they can reconstruct the anonymous payments they themselves initiated, and follow them step by step down the chain.

- **Why is money laundering a negative-EV business here? What is this trying to stop?**
  - A lot of wallet theft, scams and extortion on blockchains today depend on two properties:
    1. It is hard to claw funds back.
    2. It is relatively easy to launder funds through mixers / anonymity systems.
  - my_coin is designed so that:
    - For attackers (wallet thieves, scammers, extortionists), even if they “succeed” in stealing funds, they are very likely to either:
      - get caught, or  
      - have the corresponding funds frozen, ending up with little or no profit.
    - For launderers, participating in laundering is typically **loss-making**:
      - they earn little fee,  
      - but expose their own principal to high risk (once their account has touched tainted funds, they may need to take responsibility unless they can cleanly prove where the funds went).
  - More concretely: in my_coin, **every hop of laundering must go through a KYC’d account**. Once a victim uses their private key to reconstruct their outgoing anonymous transactions and follow the trail:
    - Either a given hop takes responsibility for the entire stolen amount, which is massively larger than the fee they took.
    - Or they reveal the next hop and prove the funds indeed moved on, and only remain responsible for their small commission.
  - Rational players therefore face a negative expected payoff if they participate in laundering. On top of that, victims have strong incentives to chase the chain step by step, making it hard for a laundering ecosystem to form. Even irrational players, if they want to gamble for a big upside, would be better off buying lottery tickets than using my_coin’s anonymous payment features to launder funds.

- **What is already implemented in this repo (ZK-based prototype)**
  - A single-node blockchain prototype + Rust zero-knowledge proof modules + Python bindings.
  - 5 end-to-end demos:
    - opening anonymous payment permission (blue address) with KYC,
    - regular (non-anonymous) payments,
    - moving funds from a public account into the anonymous pool,
    - anonymous payments (payer hidden but amount still public),
    - and using a private key to reconstruct the anonymous payments initiated by that key, as a basis for tracing stolen funds.
  - If you only want to play with the demos or read the code, you can jump to **5. Prototype Overview & Demo List** and **6. How to run the demos**.

---

## What did I do in this project?

> In short, I designed the protocol and drove it from “idea → spec” all the way to a single-node prototype with integrated ZK modules.
> Most Rust circuit code was drafted with LLM assistance, but the circuit semantics, interfaces, integration, and testing were all done by me.

My work falls into two layers: **protocol design** and **single-node prototype implementation**.

- On the **protocol design** layer, I did:

  - Designed an **account permission model**:
    - Every address has a state (you can think of it as an extra property attached to the address).
    - Only addresses that have completed KYC and signed the user agreement can be marked as “allowed to initiate anonymous payments”.
    - Ordinary addresses can receive and send regular transfers, but cannot use the anonymous payment feature.

  - Designed the overall structure of the **anonymous pool / non-anonymous pool**, and the idea of a **dynamic custody fee mechanism**:
    - Funds in the non-anonymous pool are charged a small custody fee over time.
    - When the anonymous pool holds a low fraction of total funds, the custody fee for the non-anonymous pool is increased to encourage funds to move into the anonymous pool.
    - When the anonymous pool is large enough, the custody fee can be reduced.
    - The goal is to push as much liquidity as possible into the anonymous pool, increasing the anonymity set and improving privacy.
    - This part is currently **only a design idea** and is **not implemented in the prototype** yet.

  - Designed the “anonymous payments + ex-post accountability” rules:
    - To ordinary observers, you cannot see who is paying in each anonymous payment (see 3.2 below).
    - But as long as an account holder still knows their private key, they can reconstruct the anonymous payments they themselves initiated and use that to assist in fund recovery.
    - The design goal is: using this system for theft, extortion, fraud, or laundering — especially acting as the **first hop** in a laundering chain — becomes economically and legally extremely unattractive:
      - Either you end up liable for the full stolen amount,
      - or you expose downstream hops and still face legal risk.
    - The detailed game-theoretic analysis of this process is discussed in the body of the README.

- On the **prototype implementation** layer (the Python / Rust code in this repo), I did:

  - Wrote a **single-node blockchain prototype in Python**:
    - `blockchain.py / acct.py / merkle_tree.py` maintain accounts, the anonymous pool, and blockchain state.
    - Code under `client/` constructs different kinds of requests (open anonymous payment permission, regular transfers, move from account to anonymous pool, anonymous pay, etc.).
    - Code under `node/` validates and handles these requests, and packages valid ones into blocks.

  - With the help of ChatGPT, implemented several ZK proof modules using Rust and a zero-knowledge proof library. My responsibilities here were:
    - Defining *what each operation must prove in zero knowledge*  
      (e.g. conservation of funds, the relationship between old and new balances, and ensuring the account holder can reconstruct their own anonymous payments).
    - Turning those statements into circuit interfaces, then asking the LLM to draft the Rust implementation.
    - Writing the Python ↔ Rust bindings under `wrappers/` so Python code can call those prove/verify functions.
    - Writing tests under `tests/rust_api_tests/` to check that:
      - valid inputs produce valid proofs;
      - tampering with public inputs or crafting pathological cases leads to verification failure.

  - Implemented a set of end-to-end demos (see the `demo/` directory) to show what the current prototype can do:
    - opening anonymous payment permission (blue address);
    - regular non-anonymous transfers;
    - moving funds from public accounts into the anonymous pool;
    - anonymous payments (payer hidden, amount currently still public);
    - given a private key, reconstructing the anonymous payments initiated by that key and using that to trace stolen funds.

### Tech stack at a glance

- Python 3.x: client logic, node logic, blockchain state management, demo scripts.
- Rust: Poseidon hash, circuit implementations, ZK proof generation / verification.
- Python ↔ Rust via `pyo3`.

--------------------------------------------------------------------
--------------------------------------------------------------------

## Main text: Protocol overview

> This overview does *not* go into all protocol details. For a full technical description of the protocol and circuits, please see **whitepaper_draft.md**.

## 1. What problem is my_coin trying to solve?

Today’s payment systems struggle to balance privacy and anti-money-laundering (AML):

- **Traditional banking systems**  
  - Strong AML, weak privacy.

- **Traditional privacy coins / mixers (Zcash, Tornado Cash, etc.)**  
  - Strong privacy, but criminals can easily use them to launder funds.

- **“Pseudonymous” systems like Bitcoin / Ethereum (ignoring mixer smart contracts)**  
  - Payment paths and amounts are **fully transparent**.
  - If you want anonymous payments, the payer’s address itself must stay anonymous.
  - But since payment paths are transparent, it’s hard for an address to remain anonymous for long, unless all funds come from anonymous sources like mining.

my_coin tries to combine the strengths of both worlds.

---

## 2. Goals of my_coin

- Without relying on a centralized authority or backdoor keys, use cryptography to achieve anonymous payments, while pushing the difficulty of money laundering up to (or beyond) the level of traditional banking **plus** Bitcoin without mixers.

---

## 3. Basic concepts: regular transfers / anonymous payments / anonymous receiving

### 3.1 Regular transfers

- Similar to Bitcoin: from address A to address B, amount X, everything is public.

### 3.2 my_coin anonymous payments

- For **third-party observers (including the receiver)**:
  - They can see there is an anonymous transaction of amount X going to receiver B.
  - They **do not know which specific account paid this X**.
  - They can still be sure that global funds are conserved.
  - This is implemented using zero-knowledge proofs; details are in **whitepaper_draft.md**.

### 3.3 Anonymous receiving

- This refers to the case where **the receiving address itself is not bound to a real-world identity**.
- However:
  - For any transaction (even an anonymous payment), the ledger explicitly records “address X received amount Y”.
  - This is essentially the same “pseudonymity” as in Bitcoin: addresses are not tied to identity by default, but the flows are visible.

---

## 4. Core rules of my_coin

### 4.1 “KYC + user agreement” is required for anonymous payments

- Because payment paths are hidden, an account can still enjoy anonymous payments even if the account itself is KYC’d (see 3.2).

- When opening anonymous payment permission, users must also sign a **Terms of Use** agreement:

1. If:
   - A victim can prove “I paid you X” (as long as they remember their private key, they can do this in my_coin); and  
   - You cannot provide a “reasonable” explanation for the source of the funds (what counts as reasonable is up to the court to decide),

   then the following can happen:

   - Assets under your name corresponding to that amount can be frozen — this can be on-chain or off-chain, depending on how the legal system enforces it.
   - If you can prove “I was just a launderer, I only took Y% as a laundering fee, and the rest has already been passed on to the next address”:
     - You must use your private key to prove that the funds indeed left your address.
     - And identify the “next hop” address.
     - In that case, the frozen amount can be reduced to just your actual fee/commission; the rest of the responsibility moves to the next account in the chain.

2. **Responsibility for lost private keys**:
   - When signing the agreement, you must also commit to “accepting the consequences of losing your private key”.
   - Losing a private key doesn’t just mean “you can’t get your own money back”. More seriously:
     - If your address ever received stolen funds, and you can no longer show where those funds went because you lost the key,
     - then according to the agreement you can still be held responsible for that amount.
   - To avoid giving users unbounded liability, each KYC’d account is given a **liability cap**. This cap will then limit how much anonymous payment volume the account is allowed to handle in a given period (for example, a monthly limit).

### 4.2 The same coins cannot simultaneously enjoy “anonymous receiving” and “anonymous paying”

my_coin makes a hard distinction at the protocol level:

- **To give a set of coins the ability to perform anonymous payments**:
  - They must first go through a KYC’d account.

- **If you insist on “anonymous receiving”**:
  - In other words, you let the funds go to an un-KYC’d address first.
  - The subsequent path of those coins will then be fully transparent on the ledger, unless you transparently move them into a KYC’d account later, and only then perform anonymous payments.
  - But that step of moving funds from the un-KYC’d address into a KYC’d account will publicly link the two, destroying the original “anonymous receiving” property.

> For example: if you want “nobody can tell this salary is yours”, you can have it paid to an un-KYC’d address — this is “anonymous receiving”.  
> But if you later want to *spend* that same salary anonymously within my_coin, you must first transparently move it into some KYC’d account. Once you do that, the link between that un-KYC’d address and the KYC’d account becomes public, and the original “anonymous salary” property is essentially gone.

### 4.3 Anonymous to the outside, but traceable to yourself: you can always see your own anonymous payment history

- With anonymous payments, third parties cannot see the payer (see 3.2).

- The my_coin anonymous payment protocol ensures that you, as the account holder, can **always** use your private key to reconstruct the anonymous payments that originated from your account.

However:

- You can **only** see the portion of the chain that starts from your own account.
- You still cannot see who paid for anonymous transfers that you did *not* initiate.
- The protocol does **not** require any “super-admin key” or “master system key”. No one can press a single button and unlock everyone’s anonymous history.

This “traceable to yourself” property is precisely what makes money laundering unprofitable here.

There is no master key that can decrypt everyone’s history in one go — **only** the account owner, with their own private key, can see the anonymous payments originating from their own accounts.

### 4.4 Why is money laundering “unprofitable” in my_coin?

Combined with the mechanisms above, the game-theoretic picture of money laundering in my_coin looks roughly like this.

#### 4.4.1 Look at the first hop

- Suppose a launderer wants to help a hacker clean 100,000 units of stolen funds by using their own KYC’d address:
  - They might, at most, charge a 5–10% fee (because laundering usually involves many layers and many KYC’d accounts; any single hop often can’t take that much — this is an upper bound).
  - But once this chain is discovered by the victim:
    - If this hop refuses to reveal downstream participants:
      - Under the terms of use, they can be held liable for the full 100,000, which is **orders of magnitude** larger than their fee.
    - If they want to limit their liability to just their fee:
      - They must prove that the 100,000 left their address.
      - Prove that they only kept X% as a fee.
      - And identify the next hop.
      - As long as they still have their private key, they can do all of this in my_coin.

#### 4.4.2 The dilemma for each hop in the chain

For every participant in a laundering chain, the decision looks like a binary choice:

1. **Keep silent**:  
   - Earn a small commission,  
   - But face a high probability of being discovered, especially for the first few hops closest to the source of the stolen funds — because the victim has a strong incentive to follow the trail using their private key.  
   - Once exposed, they may have to cover the **entire stolen amount**.

2. **Cooperate to reduce losses**:  
   - To avoid paying for the whole stolen amount, they must reveal downstream hops,  
   - And still face legal risk for having knowingly participated in laundering.

For all rational players, this is a **negative expected value** business. They not only have high legal risk, but the financial expectation is strongly negative.

#### 4.4.3 Result: nobody wants to be the first hop, and the chain is hard to build

Therefore:

- In theory, nobody has an incentive to be the **first hop**:
  - Neither scammers nor hackers directly want to be the first KYC’d account to touch the funds, because the risk is too high.
  - Without a credible first hop, a laundering chain is hard to start in the first place.
- Later hops also fear being exposed by earlier hops, and fear law-enforcement sting operations. With low potential income and extremely high risk, they also have little incentive.
- So laundering chains are often **hard to form from the beginning**.  
- Even if a chain does form, there is good chance to peel it back hop by hop:
  - Even if not all stolen funds are recovered, at least the first hop is likely to be found.
  - The victim can at least recover a significant portion of the loss, and those who willingly participated in laundering are very likely to face legal and financial consequences.

In summary:

- **Using my_coin to launder money is vastly more difficult than using traditional mixers / privacy coins.**
- At the same time, users can still enjoy cryptographically guaranteed anonymous payments with no backdoor.

---------------------------------------------------------------------

## Main text: Prototype overview

## 5. Prototype Overview & Demo List

This repository implements a **single-node prototype** of the my_coin protocol, to show how the “anonymous payments + ex-post accountability” mechanisms can be realized in an actual system. The current prototype mainly covers the following scenarios:

- **Blue address application (open anonymous payment permission)**
  - Simulates Alice completing KYC / signing the agreement through a Clerk and being granted the “allowed to initiate anonymous payments” status on chain.

- **Regular (non-anonymous) transfers**
  - Similar to the account model in Ethereum: sender, receiver, and amount are all public.

- **Moving funds from public accounts into the anonymous pool (acct → anon)**
  - Commit public balances into the anonymous pool as preparation for later anonymous payments.

- **Anonymous payments (payer hidden, amount currently public)**
  - Use the anonymous pool + commitments to hide the payer, while the amount is still visible to everyone.
  - The protocol guarantees: as long as the payer is willing to use their private key, they can reconstruct their own anonymous payment history.

- **Private-key-based tracing demo**
  - Given a private key, enumerate all anonymous payments initiated by the accounts controlled by that key, and use that to demonstrate how a victim can follow the chain of stolen funds.

The corresponding demo scripts in the `demo/` directory are roughly:

- `demo1_good.py`  
  - Scenario: Alice’s first application for a blue address. The Clerk endorses, the Node verifies, and the result is written into the blockchain.

- `demo1_bad.py`  
  - Scenario: various invalid / malicious blue address applications being correctly rejected by the Node.

- `demo2_good.py`  
  - Scenario: regular transparent transfers between accounts, as a base version of an Ethereum-like account model.

- `demo3_good.py` / `demo3_bad.py`  
  - Scenario: moving funds from public accounts into the anonymous pool, and examples of invalid acct→anon requests being rejected.

- `demo4_good.py` / `demo4_bad.py`  
  - Scenario: making anonymous payments (hiding the payer) through the anonymous pool, and testing various misuses / malicious requests.

- `demo5.py`  
  - Scenario: internally first runs something like `demo4_good.py` to generate a blockchain with a bunch of anonymous payments. On top of that chain, given a private key, it scans for anonymous payments initiated by that key and traces the flow of stolen funds.

> The current prototype only covers the scenarios listed above and runs in a **single-node environment**:  
> there is no P2P network, no consensus algorithm, and no multi-node replay / fork handling logic.  
> Its goal is to make the “anonymous payments + ex-post accountability” protocol mechanisms and ZK parts work end-to-end, not to serve as a production-grade blockchain implementation.

### Future work (brief)

The full protocol design envisions many further features, for example:

- Support, at the account layer, for payments that **hide the amount but not the identity**.
- Allowing anonymous pool commitments to be safely split and merged.
- Combining anonymous payments and hidden-amount payments via a two-stage path similar to the Lightning Network, to enable fast payments.
- Dynamically adjusting custody fees for the non-anonymous pool according to the proportion of total funds in the anonymous pool.
- Extending the current single-node prototype into a multi-node blockchain with P2P networking and consensus.
- Add a request_id on all requests sent from the wallet to the node.

---

## 6. How to run the demos

- The project targets a Linux environment, ideally Ubuntu 24.04.  
- My own development environment was: Windows 11, WSL 2, Ubuntu 24.04.

- You may need to install the following dependencies first:

```bash
sudo apt update && sudo apt upgrade
sudo apt install -y python3.12 python3.12-venv python3.12-dev python3-pip
```

- From the project root, create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

- Install Rust toolchain + maturin (required for building the ZK module)

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
pip install maturin

```

- Build the ZK module with maturin:

```bash
cd zkcrypto
maturin develop --release
cd ..
```


- Then you can directly run the demos, for example:

```bash
python3 demo/demo1_good.py
```