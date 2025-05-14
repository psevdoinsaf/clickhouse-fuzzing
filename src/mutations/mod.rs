mod sql_mutations;

pub use self::sql_mutations::SqlMutator;

pub trait Mutator {
    fn mutate(&self, input: &[u8]) -> Vec<u8>;
    fn is_valid(&self, input: &[u8]) -> bool;
}
