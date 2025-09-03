# PacketRusher interop

Thanks to the authors of [PacketRusher](https://github.com/HewlettPackard/PacketRusher)!

## Simple UE session establishment and teardown with PacketRusher + QCore
### Terminal 1 - QCore
```sh
cd ~/qcore && RUST_LOG=debug cargo run -- --mcc 208 --mnc 93 --local-ip 127.0.0.1 --ran-interface-name lo --sim-cred-file docs/PacketRusher-testing/sims.toml
```

### Terminal 2 - PacketRusher
```sh
cd $PACKETRUSHER && sudo ./packetrusher --config ~/qcore/docs/PacketRusher-testing/config.yml ue
``` 
