use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use base64::Engine;
use serde::de::{Error as _, IgnoredAny, SeqAccess, Visitor};
use serde::Deserialize;
use std::fmt;
use std::io::Cursor;

#[cfg(test)]
use ciborium::value::Value;

const MAX_DECODED_TOKEN_BYTES: usize = 768 * 1024;
const MAX_FUNDING_PROOFS: usize = 992;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FundingToken {
    #[serde(rename = "m")]
    _mint: String,
    #[serde(rename = "u")]
    _unit: String,
    #[serde(rename = "t", deserialize_with = "deserialize_single_group")]
    _group: FundingGroup,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FundingGroup {
    #[serde(rename = "i", deserialize_with = "deserialize_bytes_8")]
    _keyset_id: (),
    #[serde(rename = "p", deserialize_with = "deserialize_proofs")]
    _proofs: Vec<FundingProof>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FundingProof {
    #[serde(rename = "a")]
    _amount: u64,
    #[serde(rename = "s")]
    _secret: String,
    #[serde(rename = "c", deserialize_with = "deserialize_bytes_33")]
    _c: (),
    #[serde(rename = "d")]
    _dleq: FundingDleq,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FundingDleq {
    #[serde(rename = "e", deserialize_with = "deserialize_bytes_32")]
    _e: (),
    #[serde(rename = "s", deserialize_with = "deserialize_bytes_32")]
    _s: (),
    #[serde(rename = "r", deserialize_with = "deserialize_bytes_32")]
    _r: (),
}

pub fn validate_channel_funding_token_structure(token: &str) -> Result<(), String> {
    let encoded = token
        .strip_prefix("cashuB")
        .ok_or_else(|| "funding_token must use Cashu V4 cashuB encoding".to_string())?;
    let decoder = GeneralPurpose::new(
        &alphabet::URL_SAFE,
        GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
    );
    let decoded = decoder
        .decode(encoded)
        .map_err(|_| "funding_token has invalid base64url".to_string())?;
    if decoded.len() > MAX_DECODED_TOKEN_BYTES {
        return Err("funding_token exceeds decoded size limit".to_string());
    }
    let mut cursor = Cursor::new(decoded.as_slice());
    let _: FundingToken = ciborium::from_reader(&mut cursor)
        .map_err(|_| "funding_token has invalid CBOR".to_string())?;
    if cursor.position() != decoded.len() as u64 {
        return Err("funding_token has trailing CBOR data".to_string());
    }
    Ok(())
}

fn deserialize_single_group<'de, D>(deserializer: D) -> Result<FundingGroup, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct SingleGroupVisitor;

    impl<'de> Visitor<'de> for SingleGroupVisitor {
        type Value = FundingGroup;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("an array containing exactly one funding group")
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let group = sequence
                .next_element()?
                .ok_or_else(|| A::Error::custom("funding token has no keyset group"))?;
            if sequence.next_element::<IgnoredAny>()?.is_some() {
                return Err(A::Error::custom(
                    "funding token has more than one keyset group",
                ));
            }
            Ok(group)
        }
    }

    deserializer.deserialize_seq(SingleGroupVisitor)
}

fn deserialize_proofs<'de, D>(deserializer: D) -> Result<Vec<FundingProof>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct ProofsVisitor;

    impl<'de> Visitor<'de> for ProofsVisitor {
        type Value = Vec<FundingProof>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a nonempty bounded funding proof array")
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            if sequence
                .size_hint()
                .is_some_and(|size| size > MAX_FUNDING_PROOFS)
            {
                return Err(A::Error::custom("funding token contains too many proofs"));
            }
            let mut proofs =
                Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(MAX_FUNDING_PROOFS));
            while let Some(proof) = sequence.next_element()? {
                if proofs.len() == MAX_FUNDING_PROOFS {
                    return Err(A::Error::custom("funding token contains too many proofs"));
                }
                proofs.push(proof);
            }
            if proofs.is_empty() {
                return Err(A::Error::custom("funding token has no proofs"));
            }
            Ok(proofs)
        }
    }

    deserializer.deserialize_seq(ProofsVisitor)
}

fn deserialize_bytes_8<'de, D>(deserializer: D) -> Result<(), D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_exact_bytes(deserializer, 8)
}

fn deserialize_bytes_32<'de, D>(deserializer: D) -> Result<(), D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_exact_bytes(deserializer, 32)
}

fn deserialize_bytes_33<'de, D>(deserializer: D) -> Result<(), D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_exact_bytes(deserializer, 33)
}

fn deserialize_exact_bytes<'de, D>(deserializer: D, expected_len: usize) -> Result<(), D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct ExactBytesVisitor(usize);

    impl Visitor<'_> for ExactBytesVisitor {
        type Value = ();

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "a CBOR byte string containing {} bytes", self.0)
        }

        fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            if value.len() == self.0 {
                Ok(())
            } else {
                Err(E::invalid_length(value.len(), &self))
            }
        }

        fn visit_byte_buf<E>(self, value: Vec<u8>) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            self.visit_bytes(&value)
        }
    }

    deserializer.deserialize_bytes(ExactBytesVisitor(expected_len))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(value: &str) -> Value {
        Value::Text(value.to_string())
    }

    fn valid_value() -> Value {
        Value::Map(vec![
            (text("m"), text("https://mint.example")),
            (text("u"), text("sat")),
            (
                text("t"),
                Value::Array(vec![Value::Map(vec![
                    (text("i"), Value::Bytes(vec![0; 8])),
                    (
                        text("p"),
                        Value::Array(vec![Value::Map(vec![
                            (text("a"), Value::Integer(1.into())),
                            (text("s"), text("secret")),
                            (text("c"), Value::Bytes(vec![2; 33])),
                            (
                                text("d"),
                                Value::Map(vec![
                                    (text("e"), Value::Bytes(vec![3; 32])),
                                    (text("s"), Value::Bytes(vec![4; 32])),
                                    (text("r"), Value::Bytes(vec![5; 32])),
                                ]),
                            ),
                        ])]),
                    ),
                ])]),
            ),
        ])
    }

    fn encode(value: &Value) -> String {
        let mut bytes = Vec::new();
        ciborium::into_writer(value, &mut bytes).unwrap();
        format!(
            "cashuB{}",
            base64::engine::general_purpose::URL_SAFE.encode(bytes)
        )
    }

    fn field_mut<'a>(value: &'a mut Value, name: &str) -> &'a mut Value {
        value
            .as_map_mut()
            .unwrap()
            .iter_mut()
            .find_map(|(key, value)| (key.as_text() == Some(name)).then_some(value))
            .unwrap()
    }

    fn first_group_mut(value: &mut Value) -> &mut Value {
        &mut field_mut(value, "t").as_array_mut().unwrap()[0]
    }

    fn first_proof_mut(value: &mut Value) -> &mut Value {
        &mut field_mut(first_group_mut(value), "p")
            .as_array_mut()
            .unwrap()[0]
    }

    #[test]
    fn accepts_exact_single_group_v4_structure() {
        validate_channel_funding_token_structure(&encode(&valid_value())).unwrap();
    }

    #[test]
    fn rejects_memo_multiple_groups_and_unknown_proof_fields() {
        let mut memo = valid_value();
        memo.as_map_mut().unwrap().push((text("d"), text("memo")));
        assert!(validate_channel_funding_token_structure(&encode(&memo)).is_err());

        let mut multiple = valid_value();
        let groups = multiple
            .as_map_mut()
            .unwrap()
            .iter_mut()
            .find_map(|(key, value)| (key.as_text() == Some("t")).then_some(value))
            .unwrap()
            .as_array_mut()
            .unwrap();
        groups.push(groups[0].clone());
        assert!(validate_channel_funding_token_structure(&encode(&multiple)).is_err());

        let mut witness = valid_value();
        let proof = witness.as_map_mut().unwrap()[2].1.as_array_mut().unwrap()[0]
            .as_map_mut()
            .unwrap()[1]
            .1
            .as_array_mut()
            .unwrap()[0]
            .as_map_mut()
            .unwrap();
        proof.push((text("witness"), text("forbidden")));
        assert!(validate_channel_funding_token_structure(&encode(&witness)).is_err());
    }

    #[test]
    fn rejects_duplicate_and_trailing_cbor() {
        let mut duplicate = valid_value();
        duplicate
            .as_map_mut()
            .unwrap()
            .push((text("m"), text("https://other.example")));
        assert!(validate_channel_funding_token_structure(&encode(&duplicate)).is_err());

        let mut bytes = Vec::new();
        ciborium::into_writer(&valid_value(), &mut bytes).unwrap();
        bytes.push(0xf6);
        let token = format!(
            "cashuB{}",
            base64::engine::general_purpose::URL_SAFE.encode(bytes)
        );
        assert!(validate_channel_funding_token_structure(&token).is_err());
    }

    #[test]
    fn rejects_malformed_or_incomplete_structural_layers() {
        for token in ["cashuAabc", "cashuB!", "cashuBYQ=="] {
            assert!(validate_channel_funding_token_structure(token).is_err());
        }

        let mut cases = Vec::new();
        let mut no_groups = valid_value();
        field_mut(&mut no_groups, "t")
            .as_array_mut()
            .unwrap()
            .clear();
        cases.push(no_groups);

        let mut no_proofs = valid_value();
        field_mut(first_group_mut(&mut no_proofs), "p")
            .as_array_mut()
            .unwrap()
            .clear();
        cases.push(no_proofs);

        let mut unknown_group = valid_value();
        first_group_mut(&mut unknown_group)
            .as_map_mut()
            .unwrap()
            .push((text("x"), Value::Null));
        cases.push(unknown_group);

        let mut missing_proof_field = valid_value();
        first_proof_mut(&mut missing_proof_field)
            .as_map_mut()
            .unwrap()
            .retain(|(key, _)| key.as_text() != Some("c"));
        cases.push(missing_proof_field);

        let mut unknown_dleq = valid_value();
        field_mut(first_proof_mut(&mut unknown_dleq), "d")
            .as_map_mut()
            .unwrap()
            .push((text("x"), Value::Null));
        cases.push(unknown_dleq);

        let mut missing_dleq_field = valid_value();
        field_mut(first_proof_mut(&mut missing_dleq_field), "d")
            .as_map_mut()
            .unwrap()
            .retain(|(key, _)| key.as_text() != Some("r"));
        cases.push(missing_dleq_field);

        for value in cases {
            assert!(validate_channel_funding_token_structure(&encode(&value)).is_err());
        }
    }

    #[test]
    fn accepts_exact_proof_limit_and_rejects_one_more() {
        let mut source = valid_value();
        let proof = first_proof_mut(&mut source).clone();
        let mut exact_limit = valid_value();
        *field_mut(first_group_mut(&mut exact_limit), "p") =
            Value::Array(vec![proof.clone(); MAX_FUNDING_PROOFS]);
        validate_channel_funding_token_structure(&encode(&exact_limit)).unwrap();

        let mut too_many_proofs = valid_value();
        *field_mut(first_group_mut(&mut too_many_proofs), "p") =
            Value::Array(vec![proof; MAX_FUNDING_PROOFS + 1]);
        assert!(validate_channel_funding_token_structure(&encode(&too_many_proofs)).is_err());
    }
}
