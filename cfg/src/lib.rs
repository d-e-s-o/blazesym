extern crate proc_macro;

use proc_macro::TokenStream;

use std::str::FromStr as _;


#[proc_macro_attribute]
pub fn cfg_blz(attr: TokenStream, item: TokenStream) -> TokenStream {
    match attr.to_string().as_str() {
        "gsym" => {
            //panic!("GSYM");
        }
        _ => {}
    }

    item
    //panic!("{attr}\n{item}");
    //attr
}

#[proc_macro_derive(CfgBlz, attributes(gsym))]
pub fn cfg_blz_(input: TokenStream) -> TokenStream {
    TokenStream::new()
    //input
    //let code = input.to_string();
    //let gsym = r#"
    //  #[cfg_attr(docsrs, doc(cfg(feature = "gsym")))]
    //  #[cfg(feature = "gsym")]
    //"#;

    //let code = code.replace("#[gsym]", gsym);
    //TokenStream::from_str(&code).expect("generated invalid code")
}
