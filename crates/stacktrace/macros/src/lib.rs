//! Attribute macro backing `pluto-stacktrace`; use it through that crate.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{ToTokens, quote};
use syn::{
    Attribute, Error, Fields, Generics, Ident, Item, ItemEnum, ItemStruct, Meta, Token, Type,
    parse_macro_input, parse_quote, punctuated::Punctuated, spanned::Spanned,
};

/// Rewrites every unnamed `#[from] T` field of a `thiserror` type into
/// `::pluto_stacktrace::LocatedError<T>` and emits a `#[track_caller]`
/// `From<T>` impl for it.
#[proc_macro_attribute]
pub fn located(_args: TokenStream, input: TokenStream) -> TokenStream {
    let item = parse_macro_input!(input as Item);

    match expand(item) {
        Ok(tokens) => tokens.into(),
        Err(error) => error.to_compile_error().into(),
    }
}

fn expand(item: Item) -> Result<TokenStream2, Error> {
    match item {
        Item::Enum(item) => expand_enum(item),
        Item::Struct(item) => expand_struct(item),
        other => Err(Error::new(
            other.span(),
            "`located` applies to enums and structs deriving `thiserror::Error`",
        )),
    }
}

fn expand_enum(mut item: ItemEnum) -> Result<TokenStream2, Error> {
    require_thiserror(&item.attrs, &item.ident)?;

    let mut sources = Vec::new();
    for variant in &mut item.variants {
        collect_sources(&mut variant.fields, &mut sources)?;
    }

    let impls = from_impls(&item.ident, &item.generics, &sources)?;
    Ok(quote! {
        #item
        #impls
    })
}

fn expand_struct(mut item: ItemStruct) -> Result<TokenStream2, Error> {
    require_thiserror(&item.attrs, &item.ident)?;

    let mut sources = Vec::new();
    collect_sources(&mut item.fields, &mut sources)?;

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

/// Accepts `#[derive(Error)]` and `#[derive(thiserror::Error)]`.
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
            Meta::Path(path) => {
                path.is_ident("Error") || {
                    let path = path.into_token_stream().to_string();
                    path.contains("thiserror") && path.contains("Error")
                }
            }
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
