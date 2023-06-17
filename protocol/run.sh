export ADDR="127.0.0.1:11452"
export SECRET_PLAIN="hey! secret key!"
export SECRET=$(echo -n $SECRET_PLAIN | base64)
export RUST_LOG=trace

# run A if $1 == "A", run B if $1 == "B"
if [ x"$1" == x"A" ]; then
    cargo run --bin A
elif [ x"$1" == x"B" ]; then
    cargo run --bin B
else
    echo "Usage: $0 A|B"
fi
