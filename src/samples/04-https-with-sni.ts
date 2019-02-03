/**
 * Copyright 2019 Angus.Fenying <fenying@litert.org>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// tslint:disable:no-console

import * as libsni from "../libs";
import * as HTTPS from "https";
import * as FS from "fs";

const CA_CERT = FS.readFileSync(`${__dirname}/../test/ca/cert.pem`);

const cm = libsni.certs.createManager();

for (const name of [
    "a.local.org",
    "b.local.org",
    "x.local.org"
]) {

    cm.use(
        name,
        FS.readFileSync(`${__dirname}/../test/certs/${name}/cert.pem`),
        FS.readFileSync(`${__dirname}/../test/certs/${name}/key.pem`),
        {
            ca: [ CA_CERT ]
        }
    );
}

const server = HTTPS.createServer({
    SNICallback: cm.getSNICallback(),
    requestCert: false
}, function(req, resp): void {

    console.info(`Server: New connection for ${req.headers["host"]}.`);

    resp.setHeader("Content-Length", 5);
    resp.end("Hello", () => console.info("Server: Response sent."));
});

server.listen(443, "127.0.0.1", function(): void {

    console.info("Server: started");

    for (const hostname of [
        "a.local.org",
        "b.local.org",
        "c.local.org",
        "local.org",
        "dddd.local.org",
        "g.local.org",
        "x.local.org",
        "www.c.local.org"
    ]) {

        HTTPS.request({
            host: hostname,
            port: 443,
            path: "/",
            method: "GET",
            ca: [ CA_CERT ]
        }, (resp) => {
            console.info(`Client[${hostname}]: Connected.`);
            resp.on(
                "data",
                function(chunk: Buffer): void {

                    console.info(`Client[${hostname}]: Received data "${chunk.toString()}".`);
                }
            );
        }).on("error", (e) => console.error(`Client[${hostname}]: ${e.stack}`)).end();
    }

    setTimeout(() => server.close(() => console.info(`Server: closed`)), 5000);
}).on(
    "error",
    (e) => console.error(`Server: ${e.toString()}`)
);
