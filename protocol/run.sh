export ADDR="127.0.0.1:11452"
export SECRET_PLAIN="hey! secret key!"
export SECRET=$(echo -n $SECRET_PLAIN | base64)
export RUST_LOG=trace

# run A if $1 == "A", run B if $1 == "B"
if [ x"$1" == x"a" ]; then
    cargo run --bin a
elif [ x"$1" == x"b" ]; then
    cargo run --bin b
else
    echo "Usage: $0 a|b"
fi
