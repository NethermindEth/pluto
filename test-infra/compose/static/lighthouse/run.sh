#!/usr/bin/env bash

while ! curl "http://${NODE}:3600/up" 2>/dev/null; do
  echo "Waiting for http://${NODE}:3600/up to become available..."
  sleep 5
done

echo "Creating testnet config"
rm -rf /tmp/testnet || true
mkdir /tmp/testnet/
curl "http://${NODE}:3600/eth/v1/config/spec" | jq -r .data | yq -P > /tmp/testnet/config.yaml
echo "0" > /tmp/testnet/deploy_block.txt
echo "0" > /tmp/testnet/deposit_contract_block.txt

for f in /compose/"${NODE}"/validator_keys/keystore-*.json; do
  echo "Importing key ${f}"
  # --password-file instead of charon's stdin pipe: lighthouse v7 prompts on
  # the tty and dies with "Error reading from tty" in a docker container,
  # leaving the VC with zero validators.
  lighthouse account validator import \
    --testnet-dir "/tmp/testnet" \
    --keystore "${f}" \
    --password-file "$(echo "${f}" | sed 's/json/txt/')" \
    --reuse-password
done


echo "Starting lighthouse validator client for ${NODE}"
exec lighthouse validator \
  --testnet-dir "/tmp/testnet" \
  --beacon-nodes "http://${NODE}:3600" \
  --suggested-fee-recipient "0x0000000000000000000000000000000000000000"
