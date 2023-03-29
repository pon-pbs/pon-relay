# Welcome To Proof Of Neutrality Relay
The Proof of Neutrality Relay (PoN) is a decentralized, permissionless, and neutral middleware run by validators to participate in the market for block-building and exchange. The PoN relay was built by Blockswap Labs as a solution implementing the <a href="/pon/key-concepts" >Proposer-Builder Separation theory</a>
(PBS) put forward by Vitalik Buterin.

### Why build the Proof of Neutrality Relay?

Ethereum’s credible neutrality and decentralization of consensus is under threat from centralized relays and censorship caused by MEV. The PoN relay’s decentralized infrastructure is necessary to prevent a world of permissioned communication between block-builders and block proposers.

Validators and MEV will become more closely linked in a Proof-of-Stake (PoS) environment due to the appeal of higher MEV staking rewards and their growing importance as staking participation increases and rewards will inevitably decrease. The PoN relay maximizes validator staking rewards through the selling of blockspace to an open market, allowing for consistent MEV payouts from the <a href="/pon/key-concepts" >PBS Smoothing Pool</a>.

### How does the Proof of Neutrality Relay Work?


In the Ethereum Proof-of-Stake (PoS) system, node operators use three essential pieces of software components: the validator client, the execution client, and the consensus client. The PoN relay is an additional open-source software that seamlessly integrates with the consensus client, allowing for connection to a network of block-builders and the outsourcing of block-building. Additionally, it uses [zero-knowledge proofs]("https://ethereum.org/en/zero-knowledge-proofs/") and encrypted communication to facilitate the builder’s request for a validator, ensuring guaranteed validator payment inclusion in a block while also keeping block content unrevealed.
 
Block-builders create full blocks aiming for the optimal MEV extraction and equitable distribution of rewards. Once they are done, the blocks are sent to relays. The PoN relay selects the most profitable block received from various builders, submits it to the block proposer, and the consensus client then sends it to the Ethereum network for verification and block inclusion. 

Reporters are a novel addition and essential for a decentralized infrastructure to run smoothly. In the PoN relay, reporters monitor the actions of builders and proposers to ensure that there is no malicious behavior or wrongdoing. If a violation occurs, the reporter can submit a report and earn ETH for securing the protocol.


### Whitelisted Relays

---
Relay ECDSA: Relay BLS Public Key: Relay API
0x4b7D8790bE2000cCCDBa4b8Ef4F2f76A5ccd1427: 0x89daf9bf6113ec91fdbee11778ab1e1bb64f4ccc2532bdc2bb808c93a83946ac36bce00cf2496ce2b19a20f0030cd2bd: relayer.0xblockswap.com
id: pon
---

### Getting Your Relay Whitelisted

Make a PR that adds your details to whitelisted relay table and we will approve your relay and add to the payout pool.