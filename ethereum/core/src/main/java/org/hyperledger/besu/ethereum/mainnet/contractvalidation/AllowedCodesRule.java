package org.hyperledger.besu.ethereum.mainnet.contractvalidation;

import static org.hyperledger.besu.crypto.Hash.keccak256;

import org.hyperledger.besu.ethereum.core.Hash;
import org.hyperledger.besu.ethereum.mainnet.ContractValidationRule;
import org.hyperledger.besu.ethereum.vm.MessageFrame;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.tuweni.bytes.Bytes;

public class AllowedCodesRule implements ContractValidationRule {

  private static final Logger LOG = LogManager.getLogger();

  private final ArrayList<Map.Entry<Long, Set<Hash>>> allowedCodes;

  private AllowedCodesRule(final Map<Long, List<String>> allowedCodes) {
    this.allowedCodes =
        allowedCodes.entrySet().stream()
            .sorted(Map.Entry.<Long, List<String>>comparingByKey())
            .map(
                e ->
                    Map.entry(
                        e.getKey(),
                        e.getValue().stream()
                            .map(s -> Hash.fromHexString(s))
                            .collect(Collectors.toSet())))
            .collect(Collectors.toCollection(ArrayList::new));
  }

  @Override
  public boolean validate(final MessageFrame frame) {
    final Bytes contractCode = frame.getOutputData();
    final long blockNumber = frame.getBlockHeader().getNumber();
    final Hash codeHash = Hash.wrap(keccak256(contractCode));

    if (getAllowedCodesFor(blockNumber).contains(codeHash)) {
      return true;
    } else {
      LOG.info(
          "Contract creation error: code (hash {}) is not included in allowed codes", codeHash);
      return false;
    }
  }

  private Set<Hash> getAllowedCodesFor(final long blockNumber) {
    int idx =
        Collections.binarySearch(
            allowedCodes,
            Map.entry(blockNumber, Collections.emptySet()),
            Map.Entry.<Long, Set<Hash>>comparingByKey());

    if (idx >= 0) {
      return allowedCodes.get(idx).getValue();
    } else {
      int leftIdx = -idx - 2;
      if (leftIdx >= 0) {
        return allowedCodes.get(leftIdx).getValue();
      } else {
        return Collections.emptySet();
      }
    }
  }

  public static ContractValidationRule of(final Map<Long, List<String>> allowedCodes) {
    return new AllowedCodesRule(allowedCodes);
  }
}
