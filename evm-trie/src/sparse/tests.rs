//! Sparse-trie tests and the feature-gated witness builder.

pub mod reference;

#[cfg(test)]
mod lookup;

#[cfg(test)]
mod validation;

#[cfg(test)]
mod sort;

#[cfg(test)]
mod ordered;
