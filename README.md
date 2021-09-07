# Chained Verifiable Credentials
This is an experimental implementation of using Verifiable Credential (VC) for delegation.
It uses the following information and dependencies:
* [Chained Credentials](https://github.com/hyperledger/aries-rfcs/tree/master/concepts/0104-chained-credentials)
* [Indirect Control](https://github.com/hyperledger/aries-rfcs/tree/master/concepts/0103-indirect-identity-control)
* [Simple Grant Language](https://github.com/evernym/sgl)


## Motivation
In many real-world scenarios, there's often a need to delegate the ability for an entity to `act on the behalf` of another.  This usually implies granting a subset of permissions to the delegatee. Many of today's systems use some form of role-based authentication/authorization to accomplish this, often via a some form of a centrally managed database.

The purpose of this work is to answer the question: Can VCs be used for delegation?

## Approach

### Simple Grant Language
Building off some of the original ideas and work from Daniel Hardman (see links above) we chose to explore embedding the Simple Grant Language (SGL) into a VC as part of the delegation mechanism.

SGL is a JSON based language.  It allows you to assert what `permission(s)` are granted IF the given conditions are satified.  For example:

```json
{
    "grant": ["rent", "drive"],
    "when": {"roles": "dealer"},
}
```
This rule says: `grant` the requestor `rent` and `drive` permissions, `when` the requestor has the role of `dealer`.  The language is expressive enough to be able to create more sophisticated rules:

```json
{
    "grant": ["rent", "drive"],
     "when": { "any": [
         {"roles": "regional_manager", "n": 2},
         {"roles": "board_member"},
      ]}
}
```
Here `rent` and `drive` are granted IF the requestors are either 2 `regional_manager` OR 1 `board_member`. The keyword `any` in the syntax is an OR clause

Another example:
```json
{
    "grant": ["rent", "drive"],
     "when": { "all": [
         {"roles": "regional_manager", "n": 2},
         {"roles": "board_member"},
      ]}
}
```
In this example, we change the `any` to an `all.  Now the requestors must fullfil `all` the roles. The keyword `all` = AND

Once the rules are defined, you can pass the rules and a list of `prinicpals` to the SGL engine to
determine if the rules are satified.  A prinicipal is simply a JSON object containing the `id` of the user
and the `roles` they have:

```json
{"id": "bob", "roles": ["dealer", "manager"]}
```
How the principals are determined is based on the application. SGL by itself is just a generic rules engine.

An example (pseudo code)

```python

# Single principal (bob)
principals = [{"id": "bob", "roles": ["dealer", "manager"]}]
rule = {
    "grant": ["rent", "drive"],
    "when": {"roles": "dealer"},
}

# Returns true
sgl.satisfies(principals, rule)
```
For more information on the SGL language see: https://github.com/evernym/sgl

For more examples of using it see [SGL tests](tests/test_sql.py)

### Adding SGL rules to a Verifiable Credential (VC)
The flexibility of the VC format allows us to include SGL rules for processing a VC by a verifier.
This begins to form the basis for simple delegation. You can think of this as a capability transfer:
In the example below, Bob issues the role of dealer to carol.  Giving carol the right to perform the granted permissions against some resource.  Here's an abbreviated credential with SGL rules:

```javascript
{
    "id": "bob",

    "type": ["VerifiableCredential"],

    
    "credentialSubject.proxied.permissions": {
         "grant": ["rent", "sell"],
         "when": {"roles": "dealer"}
    }

    "credentialSubject.holder.role": "dealer",
    "credentialSubject.holder.id": "carol",

    "proof":{
        "type": "Ed25519Signature2018",
        "jws": "eyJhbGciOiJSUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..."
    }
}
```
Note the permissions grant and the `holder.role` specify the same thing.  This seems redundant, 
why not just specify the permissions?  The role can provide more context, especially if matched
against an organizations trust framework.

In addition, keeping to this structure allows us to use the additional features of the SGL language 
for `aggregate` checks:

* Carol can act as dealer if granted by at least 2 `regional managers`
* Carol can act as dealer if granted by 2 regional managers OR 1 corporate board member

This gives us the ability to use VCs as authentication/authorization tools.  And the VC also provides
the information needed to generate the validated `principals` needed to check the rules. 

Using the example above we know that `bob` is the issuer and we can check that he signed the VC via the `proof`. And, we know that `carol` is the subject of the credential and she has been granted the role `dealer`.  This results in 2 principals:
```json
[
   {"id": "bob", "roles": [...]},
   {"id": "carol", "roles": ["dealer"]},
]
```
This provides the principal set needed to pass to the SGL engine to evaluate it against the rule
embedded in the VC.

### Provenance
The example above shows `bob` issuing a credential to `carol` with the given rules.  But how do we know `bob` is authorized to do that? Somehow we need to show the chain of claims that granted the capability to Carol`.   One way to do that is to embed parent credentials the can prove the ability to delegate.  Again, the flexibility of the VC format allows us to extend the format to support provenance.  For example:

```javascript
{
    "id": "bob",

    "type": ["VerifiableCredential"],

     "provenanceProofs": [
        [BOBS CREDENTIAL]
     ],

    
    "credentialSubject.proxied.permissions": {
         "grant": ["rent", "sell"],
         "when": {"roles": "dealer"}
    }

    "credentialSubject.holder.role": "dealer",
    "credentialSubject.holder.id": "carol",

    "proof":{
        "type": "Ed25519Signature2018",
        "jws": "eyJhbGciOiJSUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..."
    }
}
```
Here we extended the credential to include the field `provenanceProofs` which may 
contain 1 or more credentials that prove the capability.  In this example, it would include 
`bob`'s credential showing he has the ability to `delegate` permissions/role.
By embedding the provenance credential, we can form a "self-certifying" chain of credentials.

This forms a nested structured of `linked` credentials.  Where the `leaf` credential (`carol`'s) in this case, contains `bob`s, which may contain the credential of whoever delegated to `bob`, and on and on...  For example, say Carol's credential is a result of the following delegation chain:
```
Acme - delegated -> Frank - delegated -> Bob - delegated -> Carol. 
```
Carol's credential would contain the entire chain. The root of the chain (`acme`) would not have
any provenanced credentials:

```text
Carol.provenance[
   Bob.provenance[
      Frank.provenance[
         Acme.provenance[]
      ]
   ]
]
```
For simplicity, we base64 encode each embedded credential. To extract the chain, we start at Carol's and decode each parent credential forming a chain of credentials.  The chain is linked by the following rule: 

The `subject id` of an embedded provenance credential should equal the `issuer id` of the current 
credential. For example, in our case, `bob` (issuer ID) is issuing a credential to `carol` (subject ID). The provenance credential in carol's credential must be a credential showing `bob` as the `credentialSubject.holder.id`  This forms the chain via the links formed by `issuer -> subject`:

```text
carol -> bob -> frank -> Acme
```

Note that Acme has no provenanced credential.  The denotes it as the root.  For this work we assume the `root` is someone/thing that's trusted in the context of this application.  In a delegation scenario an empty provenanceProof signifies the `root of trust`.   To confirm that in code,  a `root of trust` is issued via a self-certified credential: The issuer and subject are the same `id` (issuer == acme, subject == acme).

Now with all of this, Carol can present her credential to a verifier using a Verifiable Presentiaton and the logic of the verifier would need to check each credential in the chain. 

### Verifier Logic
Given a single verifiable credential, we evaluate it and check the provenance chain.
Feature:  It'll all self-contained! 

First, extract the chain into a graph of credentials, walking up, from the leaf credential all the 
way to the root of trust:

```text
Carol.provenance[
   Bob.provenance[
      Frank.provenance[
         Acme.provenance[]
      ]
   ]
]
```
Then, starting from the root (acme), walk forward and apply the following logic to each credential:

For each credential in the chain:
1. Check the cryptographic signature:  Did the issuer sign it?
2. Check the credential has not been revoked.
3. If this is the root credential make sure it's self-issued: `issuer == subject`
4. Checked the parent (issuer) and child (subject) are linked. Forming a Directed Acyclic Graph (DAG)
5. Check the credential rules (grants) are a subset of the parents grants.  No grant amplification
6. Check the rules against the current principal

See [tests](tests/test_chain.py)

This works well for simple `linear` chains, but is limited when the rules related to granting permissions get complicated.  

When a verifier requests proof of 'claim' from a requestor, the requestor will assemble all credentials they feel are relevant to form the proof and submit them via a [Verifiable Presentation](https://www.w3.org/TR/vc-data-model/#presentations) (VP).  Using a VP we can allow the verifier to use more complex rules.  For example, if carol requests accesses, the verifier could respond with the following rule:

```json
{
    "grant": ["rent", "drive"],
     "when": { "all": [
         {"roles": "manager"},
         {"roles": "dealer"},
      ]}
}
```
This says, I'll grant you `rent` and `drive` if you can show proof that: you're a `dealer` and 1 `manager` has confirmed it as well: The graph might look something like this:

```text 
           acme
        ____ | ____
        |         |
      manager    manager
        |         |
        |         |
      dealer      |
        |         |
        |___ | ___|
             |
           [o o]  2 credentials
        presentation  
```
The VP would contain 2 credentials.  Carol's showing she a dealer, and another from a manager, proving they are a manager.  Both would sign the VP, and the provenance chain of each would need to be evaluated.

But, what if you have rules that may require aggregate claims further up the chain? For example (see below), what
if the role of `manager` requires the approval of 2 `regional manager`s?  The problem is determining *who* the issuer is for the claim granting a manager.  This could work if the `id` field of a VC could contain more than 1 issuer, but the current specification doesn't support that.

```text
          acme
      ______|______
      |           |
   regional    regional    <--- who's the issuer?
    manager     manager
      |           |
      -------------
            |
         manager
            |
          dealer     
```

## Key points:
* VCs can be used for simple delegation.  But additional VC fields will
need to be designed and ideally become part of the specification
* There is no standard way to determine *who* the issuer is when using aggregate rules for delegation at higher levels in a delegation graph.  The current VC specification only allows a single field.   One potential solution would be to use a multi-signature approach where 1 or more parties share a common identifier.  
* The SGL language is powerful but can be confusing sometimes in the context of VCs.  For example, simple rules have redundant fields:  `granted role` and `subject role` are the same. But more complex may not, making it hard to understand the proper way to assemble rules.  Overall it feels like SGL is often overkill for simple rules.
* It's difficult to build a good set of rules and conditions that may be applied deterministically at the machine level. Role based rules are the norm in the Enterprise, and are constructed by humans.  In complex systems, this may introduce subtle gaps that can lead to "leaking" permissions (grant amplification).  More research is needed to explore machine approaches to building complex rules. For example, using something like directed graphs to validate the flow of rules/grants
* Complex delegation models can result in large (digital size) credentials as each parent credential is embedded in the child
* Validating a chain of credentials may require at least 2 network connections PER credential:
   * 1 to get the public key to check a signature
   * another to check the revocation status of the current credential

## Revocation
This [code](./revoke/__init__.py) also includes an experimental Python implementation of the RevocationList 2020 specification. You can read more about it here: https://w3c-ccg.github.io/vc-status-rl-2020/




