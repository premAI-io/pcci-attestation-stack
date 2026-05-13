// import a from "../"

import { ClientBuilder, QueryParams, GatewayError } from "../pkg/reticle";

try {
    let client = await new ClientBuilder("https://gateway.prem.io/").build();
    // let query_params = new QueryParams().with("model", "modelmodel");

    await client.attest();
} catch (e: any) {
    if (e.kind instanceof GatewayError)
        console.log("Gateway error:", e.kind.message);
    else
        console.log(e);
}
