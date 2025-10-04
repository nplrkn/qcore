# PacketRusher interop

Thanks to the authors of [PacketRusher](https://github.com/HewlettPackard/PacketRusher)!

## 100 UE session establishment and teardown with PacketRusher + QCore
### Terminal 1 - QCore
```sh
cd ~/qcore && RUST_LOG=info cargo run --release -- --local-ip 127.0.0.1  --no-dhcp --sim-cred-file docs/PacketRusher-testing/sims.toml
```

### Terminal 2 - PacketRusher
```sh
cd $PACKETRUSHER && sudo ./packetrusher --config ~/qcore/docs/PacketRusher-testing/config.yml multi-ue -n 100 --td 5000
``` 
