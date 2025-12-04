use std::{fmt::Debug, marker::PhantomData};

/// Defines a rule for which Claims should be verified
pub trait VerificationRule<Claims> {
    type Error: Debug;

    /// Should return Ok when verification was succesfull, [`Self::Error`] if
    /// any problem occurred
    fn attest(&self, claims: &Claims) -> Result<(), Self::Error>;
}

pub trait AddRule<Claims, R: VerificationRule<Claims>> {
    type Output<C: VerificationRule<Claims>>;

    /// Adds an attestation rule to the set of rules
    /// used to verify a given set of claims
    fn add_rule(self, rule: R) -> Self::Output<R>;
}

// implementation for tuple chaining
// so we can do something like (a, (b, (c, d)))
// It's like a statically compiled fixed size array for eterogeneous types
impl<Claims, Chain, New> VerificationRule<Claims> for (New, Chain)
where
    Chain: VerificationRule<Claims>,
    New: VerificationRule<Claims>,
    New::Error: From<Chain::Error>,
{
    type Error = New::Error;
    fn attest(&self, claims: &Claims) -> Result<(), Self::Error> {
        self.1.attest(claims)?;
        self.0.attest(claims)
    }
}

/// Builder for an attestation framework
pub struct VerificationBuilder<Claims> {
    _claims: PhantomData<Claims>,
}

impl VerificationBuilder<()> {
    /// creates a new verification pipeline based on these claims
    pub const fn new<C>() -> VerificationBuilder<C> {
        VerificationBuilder {
            _claims: PhantomData,
        }
    }
}

impl<Claims, R: VerificationRule<Claims>> AddRule<Claims, R> for VerificationBuilder<Claims> {
    type Output<O: VerificationRule<Claims>> = VerificationChain<Claims, O>;
    fn add_rule(self, rule: R) -> Self::Output<R> {
        VerificationChain {
            _claims: self._claims,
            rules: rule,
        }
    }
}

/// This chain gest created when the first set of rules
/// gets added to the [`AttestationBuilder`]
pub struct VerificationChain<Claims, C: VerificationRule<Claims>> {
    _claims: PhantomData<Claims>,
    rules: C,
}

impl<Claims, C: VerificationRule<Claims>> VerificationChain<Claims, C> {
    /// Verifies a set of `claims` against the specified rules
    pub fn verify(&self, claims: &Claims) -> Result<(), C::Error> {
        self.rules.attest(claims)
    }
}

impl<Claims, C: VerificationRule<Claims>, R: VerificationRule<Claims>> AddRule<Claims, R>
    for VerificationChain<Claims, C>
where
    <R as VerificationRule<Claims>>::Error: From<C::Error>,
{
    type Output<O: VerificationRule<Claims>> = VerificationChain<Claims, (R, C)>;
    fn add_rule(self, rule: R) -> Self::Output<R> {
        VerificationChain {
            _claims: self._claims,
            rules: (rule, self.rules),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::attestation::{AddRule, VerificationBuilder, VerificationRule};

    #[derive(Debug, PartialEq)]
    struct RulesError;

    struct Uppercase;

    impl VerificationRule<&'static str> for Uppercase {
        type Error = RulesError;
        fn attest(&self, claims: &&'static str) -> Result<(), Self::Error> {
            claims
                .chars()
                .all(|c| c.is_uppercase())
                .then_some(())
                .ok_or(RulesError)
        }
    }

    #[test]
    fn test_chain() {
        VerificationBuilder::new::<&str>()
            .add_rule(Uppercase)
            .verify(&"TEST")
            .unwrap();
    }

    #[test]
    fn test_error() {
        let chain = VerificationBuilder::new::<&str>().add_rule(Uppercase);
        let result = chain.verify(&"test");

        assert_eq!(result, Err(RulesError));
    }
}
