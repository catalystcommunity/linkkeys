// Production `ResolveApplicationKeysOperation`: calls `Rp/resolve-application-keys`
// over the same pinned CSIL-RPC transport `RegularRpClient` uses for its
// other RP operations (`src/client.ts`'s `PinnedRpOperations` is the model
// this mirrors).

import { toRpResolveApplicationKeysRequestCbor, fromRpResolveApplicationKeysResponseCbor } from "../generated/codec.gen.ts";
import type { RpResolveApplicationKeysRequest, RpResolveApplicationKeysResponse } from "../generated/types.gen.ts";
import type { ResolveApplicationKeysOperation } from "./applicationKeyCache.ts";
import type { PinnedRpcTransport, RpcCallOptions } from "./rpc.ts";

export class PinnedApplicationKeyOperations implements ResolveApplicationKeysOperation {
  constructor(private readonly transport: PinnedRpcTransport) {}

  async resolveApplicationKeys(
    req: RpResolveApplicationKeysRequest,
    options?: RpcCallOptions,
  ): Promise<RpResolveApplicationKeysResponse> {
    const response = await this.transport.callWithOptions(
      "Rp",
      "resolve-application-keys",
      toRpResolveApplicationKeysRequestCbor(req),
      options,
    );
    return fromRpResolveApplicationKeysResponseCbor(response);
  }
}
