//! Property tests over untrusted SimpleX input (`docs/security-remediation-plan.md` R7/R9): event
//! parsing never panics on arbitrary JSON, and a contact link either is rejected or yields
//! exactly one command argument.

use proptest::prelude::*;

use super::commands::{connect_via_link, validate_link};
use super::events::parse_events;

fn arbitrary_json() -> impl Strategy<Value = serde_json::Value> {
    let leaf = prop_oneof![
        Just(serde_json::Value::Null),
        any::<bool>().prop_map(serde_json::Value::from),
        any::<i64>().prop_map(serde_json::Value::from),
        any::<f64>().prop_map(serde_json::Value::from),
        // Bias towards the tag/field names the parser actually looks at.
        prop_oneof![
            Just("newChatItems".to_owned()),
            Just("contactConnected".to_owned()),
            Just("contactDisconnected".to_owned()),
            Just("chatItemsStatusesUpdated".to_owned()),
            Just("directRcv".to_owned()),
            Just("rcvMsgContent".to_owned()),
            Just("text".to_owned()),
            ".*",
        ]
        .prop_map(serde_json::Value::from),
    ];
    leaf.prop_recursive(5, 64, 8, |inner| {
        let keys = prop_oneof![
            Just("type".to_owned()),
            Just("chatItems".to_owned()),
            Just("chatItem".to_owned()),
            Just("chatInfo".to_owned()),
            Just("chatDir".to_owned()),
            Just("content".to_owned()),
            Just("msgContent".to_owned()),
            Just("contact".to_owned()),
            Just("contactId".to_owned()),
            Just("meta".to_owned()),
            Just("itemStatus".to_owned()),
            Just("text".to_owned()),
            "[a-zA-Z]{1,8}",
        ];
        prop_oneof![
            proptest::collection::vec(inner.clone(), 0..4).prop_map(serde_json::Value::from),
            proptest::collection::btree_map(keys, inner, 0..6)
                .prop_map(|map| serde_json::Value::Object(map.into_iter().collect())),
        ]
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    #[test]
    fn event_parsing_never_panics(value in arbitrary_json()) {
        let _ = parse_events(value);
    }

    #[test]
    fn an_accepted_link_is_exactly_one_command_argument(link in "\\PC{0,64}|(simplex:|https://)\\PC{0,64}") {
        if validate_link(&link).is_ok() {
            let command = connect_via_link(7, &link).expect("validated");
            let parts: Vec<_> = command.split(' ').collect();
            prop_assert_eq!(parts.len(), 3, "{:?}", command);
            prop_assert_eq!(parts[2], link.as_str());
            prop_assert!(!command.contains(['\n', '\r', '\0']));
        }
    }
}
