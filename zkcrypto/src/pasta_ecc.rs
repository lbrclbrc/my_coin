// zkcrypto/src/pasta_ecc.rs
//
// Pasta Pallas curve support for key derivation and Schnorr-style signatures.
// Exposes a bytes / bool interface to Python and hides internal structures.

use pyo3::exceptions;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use pasta_curves::pallas;
use pasta_curves::group::{Group, GroupEncoding};
use pasta_curves::group::ff::PrimeField;
use pasta_curves::group::ff::Field;
use rand::rngs::OsRng;
use blake2::{Blake2b512, Digest};

type Point = pallas::Point;
type Scalar = pallas::Scalar;

/// Convert a Python object to a 32-byte array with strict length checking.
fn py_any_to_32(b: &PyAny) -> PyResult<[u8; 32]> {
    let v: Vec<u8> = b
        .extract()
        .map_err(|_| PyErr::new::<exceptions::PyTypeError, _>("expected a bytes-like object"))?;
    if v.len() != 32 {
        return Err(PyErr::new::<exceptions::PyValueError, _>(format!(
            "SK must be exactly 32 bytes, got {}",
            v.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Ok(out)
}

/// Map arbitrary bytes to a field scalar.
fn scalar_from_bytes_mod_order(bytes: &[u8]) -> Scalar {
    let mut acc = Scalar::zero();
    let mut base = Scalar::one();
    let base_256 = Scalar::from(256u64);

    for b in bytes.iter().rev() {
        let limb = Scalar::from(*b as u64);
        acc += limb * base;
        base *= base_256;
    }
    acc
}

/// Derive scalar from a 32-byte secret key.
fn scalar_from_32(sk: &[u8; 32]) -> Scalar {
    scalar_from_bytes_mod_order(sk)
}

/// Encode scalar into canonical byte representation.
fn scalar_to_bytes_canonical(s: &Scalar) -> Vec<u8> {
    let repr = s.to_repr();
    repr.as_ref().to_vec()
}

/// Decode scalar from canonical bytes.
fn scalar_from_bytes_canonical(bytes: &[u8]) -> Scalar {
    let mut repr = <Scalar as PrimeField>::Repr::default();
    repr.as_mut().copy_from_slice(bytes);
    Scalar::from_repr(repr).unwrap()
}

/// Encode an elliptic curve point to compressed bytes.
fn point_to_bytes(p: &Point) -> Vec<u8> {
    let repr = p.to_bytes();
    repr.as_ref().to_vec()
}

/// Decode an elliptic curve point from compressed bytes produced by point_to_bytes.
fn point_from_bytes(bytes: &[u8]) -> Point {
    let mut repr = <Point as GroupEncoding>::Repr::default();
    repr.as_mut().copy_from_slice(bytes);
    let ct = Point::from_bytes(&repr);
    ct.unwrap()
}

/// Hash multiple byte slices into a scalar challenge.
fn hash_to_scalar(parts: &[&[u8]]) -> Scalar {
    let mut hasher = Blake2b512::new();
    for p in parts {
        hasher.update(p);
    }
    let digest = hasher.finalize();
    scalar_from_bytes_mod_order(digest.as_ref())
}

#[pyclass]
pub struct PastaECCKeyPairs {
    // Raw 32-byte secret key.
    sk_be32: [u8; 32],
    // Cached compressed public key bytes.
    pk_bytes: Option<Vec<u8>>,
}

#[pymethods]
impl PastaECCKeyPairs {
    #[new]
    pub fn new() -> Self {
        Self {
            sk_be32: [0u8; 32],
            pk_bytes: None,
        }
    }

    /// Set the 32-byte secret key; wrong length is an error.
    pub fn set_sk_from_bytes(&mut self, b: &PyAny) -> PyResult<()> {
        self.sk_be32 = py_any_to_32(b)?;
        // SK change invalidates cached PK.
        self.pk_bytes = None;
        Ok(())
    }

    /// Return the raw 32-byte secret key.
    pub fn get_sk_bytes<'py>(&self, py: Python<'py>) -> PyResult<&'py PyBytes> {
        Ok(PyBytes::new(py, &self.sk_be32))
    }

    /// Set the compressed public key bytes.
    pub fn set_pk_from_bytes(&mut self, b: &PyAny) -> PyResult<()> {
        let v: Vec<u8> = b
            .extract()
            .map_err(|_| PyErr::new::<exceptions::PyTypeError, _>("expected a bytes-like object"))?;
        let point_repr_len = <Point as GroupEncoding>::Repr::default()
            .as_ref()
            .len();
        if v.len() != point_repr_len {
            return Err(PyErr::new::<exceptions::PyValueError, _>(format!(
                "PK must be exactly {} bytes, got {}",
                point_repr_len,
                v.len()
            )));
        }
        self.pk_bytes = Some(v);
        Ok(())
    }

    /// Derive the compressed public key from the secret key and update the cache.
    pub fn get_pk_from_sk<'py>(&mut self, py: Python<'py>) -> PyResult<&'py PyBytes> {
        let sk_scalar = scalar_from_32(&self.sk_be32);
        let g = Point::generator();
        let pk_point = g * sk_scalar;
        let pk_bytes = point_to_bytes(&pk_point);
        self.pk_bytes = Some(pk_bytes.clone());
        Ok(PyBytes::new(py, &pk_bytes))
    }

    /// Sign a message and return signature bytes in the form R_compressed || s_bytes.
    pub fn sign<'py>(&mut self, py: Python<'py>, msg: &PyAny) -> PyResult<&'py PyBytes> {
        let m: Vec<u8> = msg
            .extract()
            .map_err(|_| PyErr::new::<exceptions::PyTypeError, _>(
                "message must be bytes-like",
            ))?;

        let x = scalar_from_32(&self.sk_be32);

        let g = Point::generator();
        let pk_point = g * x;
        let pk_bytes = point_to_bytes(&pk_point);
        self.pk_bytes = Some(pk_bytes.clone());

        let k = Scalar::random(&mut OsRng);

        let r_point = g * k;
        let r_bytes = point_to_bytes(&r_point);

        let e = hash_to_scalar(&[&r_bytes, &pk_bytes, &m]);

        let s = k + e * x;

        let s_bytes = scalar_to_bytes_canonical(&s);

        let mut sig = Vec::with_capacity(r_bytes.len() + s_bytes.len());
        sig.extend_from_slice(&r_bytes);
        sig.extend_from_slice(&s_bytes);

        Ok(PyBytes::new(py, &sig))
    }

    /// Verify a signature against a message using the cached public key.
    pub fn verify(&self, msg: &PyAny, sig_any: &PyAny) -> PyResult<bool> {
        let m: Vec<u8> = msg
            .extract()
            .map_err(|_| PyErr::new::<exceptions::PyTypeError, _>(
                "message must be bytes-like",
            ))?;
        let sig: Vec<u8> = sig_any
            .extract()
            .map_err(|_| PyErr::new::<exceptions::PyTypeError, _>(
                "signature must be bytes-like",
            ))?;

        let point_repr_len = <Point as GroupEncoding>::Repr::default()
            .as_ref()
            .len();
        let scalar_bytes_len = scalar_to_bytes_canonical(&Scalar::zero()).len();
        let expected_len = point_repr_len + scalar_bytes_len;

        if sig.len() != expected_len {
            return Ok(false);
        }

        let (r_part, s_part) = sig.split_at(point_repr_len);

        let r_point = point_from_bytes(r_part);

        let s = scalar_from_bytes_canonical(s_part);

        let pk_bytes = self
            .pk_bytes
            .as_ref()
            .expect("pk_bytes must be set before verify()");
        let pk_point = point_from_bytes(pk_bytes);

        let r_bytes = point_to_bytes(&r_point);
        let e = hash_to_scalar(&[&r_bytes, pk_bytes.as_slice(), &m]);

        let g = Point::generator();
        let lhs = g * s;
        let rhs = r_point + pk_point * e;

        Ok(lhs == rhs)
    }
}

/// Register this class in the Python module.
pub fn register_pasta_ecc(m: &PyModule) -> PyResult<()> {
    m.add_class::<PastaECCKeyPairs>()?;
    Ok(())
}
