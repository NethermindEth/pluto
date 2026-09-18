//! Attribute macro backing `pluto-stacktrace`; use it through that crate.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{
    Attribute, Data, DeriveInput, Error, Fields, Generics, Ident, Meta, Token, Type,
    parse_macro_input, parse_quote, punctuated::Punctuated, spanned::Spanned,
};

/// Rewrites every unnamed `#[from] T` field of a `thiserror` type into
/// `::pluto_stacktrace::LocatedError<T>` and emits a `#[track_caller]`
/// `From<T>` impl for it.
#[proc_macro_attribute]
pub fn located(_args: TokenStream, input: TokenStream) -> TokenStream {
    let item = parse_macro_input!(input as DeriveInput);

    match expand(item) {
        Ok(tokens) => tokens.into(),
        Err(error) => error.to_compile_error().into(),
    }
}

fn expand(mut item: DeriveInput) -> Result<TokenStream2, Error> {
    require_thiserror(&item.attrs, &item.ident)?;

    let mut sources = Vec::new();
    match &mut item.data {
        Data::Enum(data) => {
            for variant in &mut data.variants {
                collect_sources(&mut variant.fields, &mut sources)?;
            }
        }
        Data::Struct(data) => collect_sources(&mut data.fields, &mut sources)?,
        Data::Union(data) => {
            return Err(Error::new(
                data.union_token.span(),
                "`located` applies to enums and structs deriving `thiserror::Error`",
            ));
        }
    }

    let impls = from_impls(&item.ident, &item.generics, &sources)?;
    Ok(quote! {
        #item
        #impls
    })
}

/// Rewrites the `#[from]` fields in place and reports the types they held.
fn collect_sources(fields: &mut Fields, sources: &mut Vec<Type>) -> Result<(), Error> {
    match fields {
        Fields::Unnamed(fields) => {
            for field in &mut fields.unnamed {
                if has_from(&field.attrs) {
                    let source = field.ty.clone();
                    field.ty = parse_quote!(::pluto_stacktrace::LocatedError<#source>);
                    sources.push(source);
                }
            }
        }
        Fields::Named(fields) => {
            for field in &fields.named {
                if has_from(&field.attrs) {
                    return Err(Error::new(
                        field.span(),
                        "`located` only instruments unnamed `#[from]` fields; make this field \
                         positional",
                    ));
                }
            }
        }
        Fields::Unit => {}
    }

    Ok(())
}

fn from_impls(ident: &Ident, generics: &Generics, sources: &[Type]) -> Result<TokenStream2, Error> {
    if sources.is_empty() {
        return Err(Error::new(
            ident.span(),
            "`located` requires at least one unnamed `#[from]` field",
        ));
    }

    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let impls = sources.iter().map(|source| {
        quote! {
            impl #impl_generics ::core::convert::From<#source> for #ident #ty_generics
                #where_clause
            {
                #[track_caller]
                fn from(error: #source) -> Self {
                    <Self as ::core::convert::From<::pluto_stacktrace::LocatedError<#source>>>::from(
                        ::pluto_stacktrace::LocatedError::from(error),
                    )
                }
            }
        }
    });

    Ok(quote! { #(#impls)* })
}

/// Accepts any derive whose path ends in `Error`.
fn require_thiserror(attrs: &[Attribute], ident: &Ident) -> Result<(), Error> {
    let derives_error = attrs
        .iter()
        .filter(|attr| attr.path().is_ident("derive"))
        .filter_map(|attr| {
            attr.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
                .ok()
        })
        .flatten()
        .any(|meta| match meta {
            Meta::Path(path) => path
                .segments
                .last()
                .is_some_and(|segment| segment.ident == "Error"),
            Meta::List(_) | Meta::NameValue(_) => false,
        });

    if derives_error {
        Ok(())
    } else {
        Err(Error::new(
            ident.span(),
            "`located` requires `#[derive(thiserror::Error)]` on the same item",
        ))
    }
}

fn has_from(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| attr.path().is_ident("from"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expand_err(item: DeriveInput) -> String {
        expand(item).expect_err("expansion rejected").to_string()
    }

    #[test]
    fn accepts_every_spelling_of_the_thiserror_derive() {
        for derive in ["Error", "thiserror::Error", "::thiserror::Error"] {
            let path: syn::Path = syn::parse_str(derive).expect("a derive path");
            let item: DeriveInput = parse_quote! {
                #[derive(Debug, #path)]
                struct Wrapper(#[from] Leaf);
            };

            assert!(expand(item).is_ok(), "{derive}");
        }
    }

    #[test]
    fn rejects_a_derive_that_only_looks_like_thiserror() {
        let item: DeriveInput = parse_quote! {
            #[derive(my_thiserror::NotAnError)]
            struct Wrapper(#[from] Leaf);
        };

        assert!(expand_err(item).contains("requires `#[derive(thiserror::Error)]`"));
    }

    #[test]
    fn rejects_an_item_without_the_thiserror_derive() {
        let item: DeriveInput = parse_quote! {
            #[derive(Debug)]
            struct Wrapper(#[from] Leaf);
        };

        assert!(expand_err(item).contains("requires `#[derive(thiserror::Error)]`"));
    }

    #[test]
    fn rejects_a_named_from_field() {
        let item: DeriveInput = parse_quote! {
            #[derive(thiserror::Error)]
            struct Wrapper {
                #[from]
                source: Leaf,
            }
        };

        assert!(expand_err(item).contains("only instruments unnamed `#[from]` fields"));
    }

    #[test]
    fn rejects_an_item_without_any_from_field() {
        let item: DeriveInput = parse_quote! {
            #[derive(thiserror::Error)]
            enum Wrapper {
                Leaf(Leaf),
            }
        };

        assert!(expand_err(item).contains("requires at least one unnamed `#[from]` field"));
    }

    #[test]
    fn rejects_a_union() {
        let item: DeriveInput = parse_quote! {
            #[derive(thiserror::Error)]
            union Wrapper {
                leaf: u32,
            }
        };

        assert!(expand_err(item).contains("applies to enums and structs"));
    }

    #[test]
    fn carries_the_generics_onto_the_from_impl() {
        let item: DeriveInput = parse_quote! {
            #[derive(thiserror::Error)]
            enum WalkError<H: HashWalker> where H: Send {
                Leaf(#[from] Leaf),
            }
        };
        let tokens = expand(item).expect("expansion succeeded").to_string();

        assert!(
            tokens.contains(
                "impl < H : HashWalker > :: core :: convert :: From < Leaf > for WalkError < H > \
                 where H : Send"
            ),
            "{tokens}"
        );
    }

    #[test]
    fn rewrites_the_from_field_to_a_located_error() {
        let item: DeriveInput = parse_quote! {
            #[derive(thiserror::Error)]
            enum Wrapper {
                Leaf(#[from] Leaf),
            }
        };
        let tokens = expand(item).expect("expansion succeeded").to_string();

        assert!(
            tokens.contains(":: pluto_stacktrace :: LocatedError < Leaf >"),
            "{tokens}"
        );
    }
}
