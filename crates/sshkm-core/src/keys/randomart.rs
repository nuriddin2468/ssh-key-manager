//! The picture `ssh-keygen -lv` draws of a fingerprint ("randomart", the
//! drunken bishop of `sshkey.c`): easier to compare at a glance than the
//! fingerprint's text.

/// Width and height of the field.
const WIDTH: usize = 17;
const HEIGHT: usize = 9;
/// A square visited more often gets a later symbol; `S` and `E` mark where
/// the walk started and ended.
const SYMBOLS: &[u8] = b" .o+=*BOX@%&#/^SE";

/// The randomart of `digest` (the fingerprint's hash), framed as
/// `ssh-keygen` frames it: `title` (`ED25519 256`) on top, `hash`
/// (`SHA256`) below, eleven lines without a final newline.
pub(crate) fn randomart(digest: &[u8], title: &str, hash: &str) -> String {
    let top = SYMBOLS.len() - 1;
    let mut field = [[0usize; HEIGHT]; WIDTH];
    let (mut x, mut y) = (WIDTH / 2, HEIGHT / 2);
    for &byte in digest {
        let mut input = byte;
        for _ in 0..4 {
            x = if input & 1 == 1 {
                (x + 1).min(WIDTH - 1)
            } else {
                x.saturating_sub(1)
            };
            y = if input & 2 == 2 {
                (y + 1).min(HEIGHT - 1)
            } else {
                y.saturating_sub(1)
            };
            if field[x][y] < top - 2 {
                field[x][y] += 1;
            }
            input >>= 2;
        }
    }
    field[WIDTH / 2][HEIGHT / 2] = top - 1;
    field[x][y] = top;

    let mut lines = vec![border(&format!("[{title}]"))];
    for row in 0..HEIGHT {
        let cells: String = (0..WIDTH)
            .map(|column| char::from(SYMBOLS[field[column][row].min(top)]))
            .collect();
        lines.push(format!("|{cells}|"));
    }
    lines.push(border(&format!("[{hash}]")));
    lines.join("\n")
}

/// `+--[label]--+`, the label centred as `ssh-keygen` centres it (left of
/// centre when it can't be exact); a label too long for the frame is left
/// out.
fn border(label: &str) -> String {
    let label = if label.len() <= WIDTH { label } else { "" };
    let before = (WIDTH - label.len()) / 2;
    let after = WIDTH - label.len() - before;
    format!("+{}{label}{}+", "-".repeat(before), "-".repeat(after))
}

#[cfg(test)]
mod tests {
    use base64ct::{Base64Unpadded, Encoding};

    use super::*;

    /// `ssh-keygen -lv` for two fixtures (`openssh_ed25519.pub`, `rsa_pem.pub`).
    #[test]
    fn draws_what_ssh_keygen_draws() {
        let cases = [
            (
                "76vvbGumhP/HpDH4tlyySHWs5hgRZJHr2wQ7hSDwRK8",
                "ED25519 256",
                "\
+--[ED25519 256]--+
|  .oo   +o       |
|   o...o.        |
|    .....o       |
|     .  +...     |
|    E  .S=. o    |
|       .=++o.    |
|      . +*=*.    |
|       +.XO+o    |
|        *@&=     |
+----[SHA256]-----+",
            ),
            (
                "q5EZ02CpbogtN4UBn+7+kGVPIR9dbAr2WBXRBckW8Ew",
                "RSA 2048",
                "\
+---[RSA 2048]----+
|.        o**E=.  |
| o .  oo..o+=    |
|  + ..*=.o .o    |
| . o =.=o        |
|  o = = S        |
| + B o = .       |
|o O o = .        |
| + +   o         |
|  ... .          |
+----[SHA256]-----+",
            ),
        ];
        for (fingerprint, title, expected) in cases {
            let digest = Base64Unpadded::decode_vec(fingerprint).unwrap();
            assert_eq!(randomart(&digest, title, "SHA256"), expected);
        }
    }

    #[test]
    fn long_titles_are_left_out() {
        let art = randomart(&[0; 32], "A TITLE MUCH TOO LONG", "SHA256");
        assert!(art.starts_with("+-----------------+\n"));
    }
}
