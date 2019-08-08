#!/usr/bin/env node

/* eslint-disable max-len, flowtype/require-valid-file-annotation, flowtype/require-return-type */
/* global packageInformationStores, null, $$SETUP_STATIC_TABLES */

// Used for the resolveUnqualified part of the resolution (ie resolving folder/index.js & file extensions)
// Deconstructed so that they aren't affected by any fs monkeypatching occuring later during the execution
const {statSync, lstatSync, readlinkSync, readFileSync, existsSync, realpathSync} = require('fs');

const Module = require('module');
const path = require('path');
const StringDecoder = require('string_decoder');

const ignorePattern = null ? new RegExp(null) : null;

const pnpFile = path.resolve(__dirname, __filename);
const builtinModules = new Set(Module.builtinModules || Object.keys(process.binding('natives')));

const topLevelLocator = {name: null, reference: null};
const blacklistedLocator = {name: NaN, reference: NaN};

// Used for compatibility purposes - cf setupCompatibilityLayer
const patchedModules = [];
const fallbackLocators = [topLevelLocator];

// Matches backslashes of Windows paths
const backwardSlashRegExp = /\\/g;

// Matches if the path must point to a directory (ie ends with /)
const isDirRegExp = /\/$/;

// Matches if the path starts with a valid path qualifier (./, ../, /)
// eslint-disable-next-line no-unused-vars
const isStrictRegExp = /^\.{0,2}\//;

// Splits a require request into its components, or return null if the request is a file path
const pathRegExp = /^(?![a-zA-Z]:[\\\/]|\\\\|\.{0,2}(?:\/|$))((?:@[^\/]+\/)?[^\/]+)\/?(.*|)$/;

// Keep a reference around ("module" is a common name in this context, so better rename it to something more significant)
const pnpModule = module;

/**
 * Used to disable the resolution hooks (for when we want to fallback to the previous resolution - we then need
 * a way to "reset" the environment temporarily)
 */

let enableNativeHooks = true;

/**
 * Simple helper function that assign an error code to an error, so that it can more easily be caught and used
 * by third-parties.
 */

function makeError(code, message, data = {}) {
  const error = new Error(message);
  return Object.assign(error, {code, data});
}

/**
 * Ensures that the returned locator isn't a blacklisted one.
 *
 * Blacklisted packages are packages that cannot be used because their dependencies cannot be deduced. This only
 * happens with peer dependencies, which effectively have different sets of dependencies depending on their parents.
 *
 * In order to deambiguate those different sets of dependencies, the Yarn implementation of PnP will generate a
 * symlink for each combination of <package name>/<package version>/<dependent package> it will find, and will
 * blacklist the target of those symlinks. By doing this, we ensure that files loaded through a specific path
 * will always have the same set of dependencies, provided the symlinks are correctly preserved.
 *
 * Unfortunately, some tools do not preserve them, and when it happens PnP isn't able anymore to deduce the set of
 * dependencies based on the path of the file that makes the require calls. But since we've blacklisted those paths,
 * we're able to print a more helpful error message that points out that a third-party package is doing something
 * incompatible!
 */

// eslint-disable-next-line no-unused-vars
function blacklistCheck(locator) {
  if (locator === blacklistedLocator) {
    throw makeError(
      `BLACKLISTED`,
      [
        `A package has been resolved through a blacklisted path - this is usually caused by one of your tools calling`,
        `"realpath" on the return value of "require.resolve". Since the returned values use symlinks to disambiguate`,
        `peer dependencies, they must be passed untransformed to "require".`,
      ].join(` `)
    );
  }

  return locator;
}

let packageInformationStores = new Map([
  ["body-parser", new Map([
    ["1.19.0", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-body-parser-1.19.0-96b2709e57c9c4e09a6fd66a8fd979844f69f08a/node_modules/body-parser/"),
      packageDependencies: new Map([
        ["bytes", "3.1.0"],
        ["content-type", "1.0.4"],
        ["debug", "2.6.9"],
        ["depd", "1.1.2"],
        ["http-errors", "1.7.2"],
        ["iconv-lite", "0.4.24"],
        ["on-finished", "2.3.0"],
        ["qs", "6.7.0"],
        ["raw-body", "2.4.0"],
        ["type-is", "1.6.18"],
        ["body-parser", "1.19.0"],
      ]),
    }],
  ])],
  ["bytes", new Map([
    ["3.1.0", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-bytes-3.1.0-f6cf7933a360e0588fa9fde85651cdc7f805d1f6/node_modules/bytes/"),
      packageDependencies: new Map([
        ["bytes", "3.1.0"],
      ]),
    }],
  ])],
  ["content-type", new Map([
    ["1.0.4", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-content-type-1.0.4-e138cc75e040c727b1966fe5e5f8c9aee256fe3b/node_modules/content-type/"),
      packageDependencies: new Map([
        ["content-type", "1.0.4"],
      ]),
    }],
  ])],
  ["debug", new Map([
    ["2.6.9", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-debug-2.6.9-5d128515df134ff327e90a4c93f4e077a536341f/node_modules/debug/"),
      packageDependencies: new Map([
        ["ms", "2.0.0"],
        ["debug", "2.6.9"],
      ]),
    }],
  ])],
  ["ms", new Map([
    ["2.0.0", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-ms-2.0.0-5608aeadfc00be6c2901df5f9861788de0d597c8/node_modules/ms/"),
      packageDependencies: new Map([
        ["ms", "2.0.0"],
      ]),
    }],
    ["2.1.1", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-ms-2.1.1-30a5864eb3ebb0a66f2ebe6d727af06a09d86e0a/node_modules/ms/"),
      packageDependencies: new Map([
        ["ms", "2.1.1"],
      ]),
    }],
    ["2.1.2", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-ms-2.1.2-d09d1f357b443f493382a8eb3ccd183872ae6009/node_modules/ms/"),
      packageDependencies: new Map([
        ["ms", "2.1.2"],
      ]),
    }],
  ])],
  ["depd", new Map([
    ["1.1.2", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-depd-1.1.2-9bcd52e14c097763e749b274c4346ed2e560b5a9/node_modules/depd/"),
      packageDependencies: new Map([
        ["depd", "1.1.2"],
      ]),
    }],
  ])],
  ["http-errors", new Map([
    ["1.7.2", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-http-errors-1.7.2-4f5029cf13239f31036e5b2e55292bcfbcc85c8f/node_modules/http-errors/"),
      packageDependencies: new Map([
        ["depd", "1.1.2"],
        ["inherits", "2.0.3"],
        ["setprototypeof", "1.1.1"],
        ["statuses", "1.5.0"],
        ["toidentifier", "1.0.0"],
        ["http-errors", "1.7.2"],
      ]),
    }],
    ["1.7.3", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-http-errors-1.7.3-6c619e4f9c60308c38519498c14fbb10aacebb06/node_modules/http-errors/"),
      packageDependencies: new Map([
        ["depd", "1.1.2"],
        ["inherits", "2.0.4"],
        ["setprototypeof", "1.1.1"],
        ["statuses", "1.5.0"],
        ["toidentifier", "1.0.0"],
        ["http-errors", "1.7.3"],
      ]),
    }],
  ])],
  ["inherits", new Map([
    ["2.0.3", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-inherits-2.0.3-633c2c83e3da42a502f52466022480f4208261de/node_modules/inherits/"),
      packageDependencies: new Map([
        ["inherits", "2.0.3"],
      ]),
    }],
    ["2.0.4", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-inherits-2.0.4-0fa2c64f932917c3433a0ded55363aae37416b7c/node_modules/inherits/"),
      packageDependencies: new Map([
        ["inherits", "2.0.4"],
      ]),
    }],
  ])],
  ["setprototypeof", new Map([
    ["1.1.1", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-setprototypeof-1.1.1-7e95acb24aa92f5885e0abef5ba131330d4ae683/node_modules/setprototypeof/"),
      packageDependencies: new Map([
        ["setprototypeof", "1.1.1"],
      ]),
    }],
  ])],
  ["statuses", new Map([
    ["1.5.0", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-statuses-1.5.0-161c7dac177659fd9811f43771fa99381478628c/node_modules/statuses/"),
      packageDependencies: new Map([
        ["statuses", "1.5.0"],
      ]),
    }],
  ])],
  ["toidentifier", new Map([
    ["1.0.0", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-toidentifier-1.0.0-7e1be3470f1e77948bc43d94a3c8f4d7752ba553/node_modules/toidentifier/"),
      packageDependencies: new Map([
        ["toidentifier", "1.0.0"],
      ]),
    }],
  ])],
  ["iconv-lite", new Map([
    ["0.4.24", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-iconv-lite-0.4.24-2022b4b25fbddc21d2f524974a474aafe733908b/node_modules/iconv-lite/"),
      packageDependencies: new Map([
        ["safer-buffer", "2.1.2"],
        ["iconv-lite", "0.4.24"],
      ]),
    }],
  ])],
  ["safer-buffer", new Map([
    ["2.1.2", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-safer-buffer-2.1.2-44fa161b0187b9549dd84bb91802f9bd8385cd6a/node_modules/safer-buffer/"),
      packageDependencies: new Map([
        ["safer-buffer", "2.1.2"],
      ]),
    }],
  ])],
  ["on-finished", new Map([
    ["2.3.0", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-on-finished-2.3.0-20f1336481b083cd75337992a16971aa2d906947/node_modules/on-finished/"),
      packageDependencies: new Map([
        ["ee-first", "1.1.1"],
        ["on-finished", "2.3.0"],
      ]),
    }],
  ])],
  ["ee-first", new Map([
    ["1.1.1", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-ee-first-1.1.1-590c61156b0ae2f4f0255732a158b266bc56b21d/node_modules/ee-first/"),
      packageDependencies: new Map([
        ["ee-first", "1.1.1"],
      ]),
    }],
  ])],
  ["qs", new Map([
    ["6.7.0", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-qs-6.7.0-41dc1a015e3d581f1621776be31afb2876a9b1bc/node_modules/qs/"),
      packageDependencies: new Map([
        ["qs", "6.7.0"],
      ]),
    }],
  ])],
  ["raw-body", new Map([
    ["2.4.0", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-raw-body-2.4.0-a1ce6fb9c9bc356ca52e89256ab59059e13d0332/node_modules/raw-body/"),
      packageDependencies: new Map([
        ["bytes", "3.1.0"],
        ["http-errors", "1.7.2"],
        ["iconv-lite", "0.4.24"],
        ["unpipe", "1.0.0"],
        ["raw-body", "2.4.0"],
      ]),
    }],
  ])],
  ["unpipe", new Map([
    ["1.0.0", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-unpipe-1.0.0-b2bf4ee8514aae6165b4817829d21b2ef49904ec/node_modules/unpipe/"),
      packageDependencies: new Map([
        ["unpipe", "1.0.0"],
      ]),
    }],
  ])],
  ["type-is", new Map([
    ["1.6.18", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-type-is-1.6.18-4e552cd05df09467dcbc4ef739de89f2cf37c131/node_modules/type-is/"),
      packageDependencies: new Map([
        ["media-typer", "0.3.0"],
        ["mime-types", "2.1.24"],
        ["type-is", "1.6.18"],
      ]),
    }],
  ])],
  ["media-typer", new Map([
    ["0.3.0", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-media-typer-0.3.0-8710d7af0aa626f8fffa1ce00168545263255748/node_modules/media-typer/"),
      packageDependencies: new Map([
        ["media-typer", "0.3.0"],
      ]),
    }],
  ])],
  ["mime-types", new Map([
    ["2.1.24", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-mime-types-2.1.24-b6f8d0b3e951efb77dedeca194cff6d16f676f81/node_modules/mime-types/"),
      packageDependencies: new Map([
        ["mime-db", "1.40.0"],
        ["mime-types", "2.1.24"],
      ]),
    }],
  ])],
  ["mime-db", new Map([
    ["1.40.0", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-mime-db-1.40.0-a65057e998db090f732a68f6c276d387d4126c32/node_modules/mime-db/"),
      packageDependencies: new Map([
        ["mime-db", "1.40.0"],
      ]),
    }],
  ])],
  ["express", new Map([
    ["4.17.1", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-express-4.17.1-4491fc38605cf51f8629d39c2b5d026f98a4c134/node_modules/express/"),
      packageDependencies: new Map([
        ["accepts", "1.3.7"],
        ["array-flatten", "1.1.1"],
        ["body-parser", "1.19.0"],
        ["content-disposition", "0.5.3"],
        ["content-type", "1.0.4"],
        ["cookie", "0.4.0"],
        ["cookie-signature", "1.0.6"],
        ["debug", "2.6.9"],
        ["depd", "1.1.2"],
        ["encodeurl", "1.0.2"],
        ["escape-html", "1.0.3"],
        ["etag", "1.8.1"],
        ["finalhandler", "1.1.2"],
        ["fresh", "0.5.2"],
        ["merge-descriptors", "1.0.1"],
        ["methods", "1.1.2"],
        ["on-finished", "2.3.0"],
        ["parseurl", "1.3.3"],
        ["path-to-regexp", "0.1.7"],
        ["proxy-addr", "2.0.5"],
        ["qs", "6.7.0"],
        ["range-parser", "1.2.1"],
        ["safe-buffer", "5.1.2"],
        ["send", "0.17.1"],
        ["serve-static", "1.14.1"],
        ["setprototypeof", "1.1.1"],
        ["statuses", "1.5.0"],
        ["type-is", "1.6.18"],
        ["utils-merge", "1.0.1"],
        ["vary", "1.1.2"],
        ["express", "4.17.1"],
      ]),
    }],
  ])],
  ["accepts", new Map([
    ["1.3.7", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-accepts-1.3.7-531bc726517a3b2b41f850021c6cc15eaab507cd/node_modules/accepts/"),
      packageDependencies: new Map([
        ["mime-types", "2.1.24"],
        ["negotiator", "0.6.2"],
        ["accepts", "1.3.7"],
      ]),
    }],
  ])],
  ["negotiator", new Map([
    ["0.6.2", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-negotiator-0.6.2-feacf7ccf525a77ae9634436a64883ffeca346fb/node_modules/negotiator/"),
      packageDependencies: new Map([
        ["negotiator", "0.6.2"],
      ]),
    }],
  ])],
  ["array-flatten", new Map([
    ["1.1.1", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-array-flatten-1.1.1-9a5f699051b1e7073328f2a008968b64ea2955d2/node_modules/array-flatten/"),
      packageDependencies: new Map([
        ["array-flatten", "1.1.1"],
      ]),
    }],
  ])],
  ["content-disposition", new Map([
    ["0.5.3", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-content-disposition-0.5.3-e130caf7e7279087c5616c2007d0485698984fbd/node_modules/content-disposition/"),
      packageDependencies: new Map([
        ["safe-buffer", "5.1.2"],
        ["content-disposition", "0.5.3"],
      ]),
    }],
  ])],
  ["safe-buffer", new Map([
    ["5.1.2", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-safe-buffer-5.1.2-991ec69d296e0313747d59bdfd2b745c35f8828d/node_modules/safe-buffer/"),
      packageDependencies: new Map([
        ["safe-buffer", "5.1.2"],
      ]),
    }],
    ["5.2.0", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-safe-buffer-5.2.0-b74daec49b1148f88c64b68d49b1e815c1f2f519/node_modules/safe-buffer/"),
      packageDependencies: new Map([
        ["safe-buffer", "5.2.0"],
      ]),
    }],
  ])],
  ["cookie", new Map([
    ["0.4.0", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-cookie-0.4.0-beb437e7022b3b6d49019d088665303ebe9c14ba/node_modules/cookie/"),
      packageDependencies: new Map([
        ["cookie", "0.4.0"],
      ]),
    }],
  ])],
  ["cookie-signature", new Map([
    ["1.0.6", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-cookie-signature-1.0.6-e303a882b342cc3ee8ca513a79999734dab3ae2c/node_modules/cookie-signature/"),
      packageDependencies: new Map([
        ["cookie-signature", "1.0.6"],
      ]),
    }],
  ])],
  ["encodeurl", new Map([
    ["1.0.2", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-encodeurl-1.0.2-ad3ff4c86ec2d029322f5a02c3a9a606c95b3f59/node_modules/encodeurl/"),
      packageDependencies: new Map([
        ["encodeurl", "1.0.2"],
      ]),
    }],
  ])],
  ["escape-html", new Map([
    ["1.0.3", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-escape-html-1.0.3-0258eae4d3d0c0974de1c169188ef0051d1d1988/node_modules/escape-html/"),
      packageDependencies: new Map([
        ["escape-html", "1.0.3"],
      ]),
    }],
  ])],
  ["etag", new Map([
    ["1.8.1", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-etag-1.8.1-41ae2eeb65efa62268aebfea83ac7d79299b0887/node_modules/etag/"),
      packageDependencies: new Map([
        ["etag", "1.8.1"],
      ]),
    }],
  ])],
  ["finalhandler", new Map([
    ["1.1.2", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-finalhandler-1.1.2-b7e7d000ffd11938d0fdb053506f6ebabe9f587d/node_modules/finalhandler/"),
      packageDependencies: new Map([
        ["debug", "2.6.9"],
        ["encodeurl", "1.0.2"],
        ["escape-html", "1.0.3"],
        ["on-finished", "2.3.0"],
        ["parseurl", "1.3.3"],
        ["statuses", "1.5.0"],
        ["unpipe", "1.0.0"],
        ["finalhandler", "1.1.2"],
      ]),
    }],
  ])],
  ["parseurl", new Map([
    ["1.3.3", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-parseurl-1.3.3-9da19e7bee8d12dff0513ed5b76957793bc2e8d4/node_modules/parseurl/"),
      packageDependencies: new Map([
        ["parseurl", "1.3.3"],
      ]),
    }],
  ])],
  ["fresh", new Map([
    ["0.5.2", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-fresh-0.5.2-3d8cadd90d976569fa835ab1f8e4b23a105605a7/node_modules/fresh/"),
      packageDependencies: new Map([
        ["fresh", "0.5.2"],
      ]),
    }],
  ])],
  ["merge-descriptors", new Map([
    ["1.0.1", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-merge-descriptors-1.0.1-b00aaa556dd8b44568150ec9d1b953f3f90cbb61/node_modules/merge-descriptors/"),
      packageDependencies: new Map([
        ["merge-descriptors", "1.0.1"],
      ]),
    }],
  ])],
  ["methods", new Map([
    ["1.1.2", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-methods-1.1.2-5529a4d67654134edcc5266656835b0f851afcee/node_modules/methods/"),
      packageDependencies: new Map([
        ["methods", "1.1.2"],
      ]),
    }],
  ])],
  ["path-to-regexp", new Map([
    ["0.1.7", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-path-to-regexp-0.1.7-df604178005f522f15eb4490e7247a1bfaa67f8c/node_modules/path-to-regexp/"),
      packageDependencies: new Map([
        ["path-to-regexp", "0.1.7"],
      ]),
    }],
  ])],
  ["proxy-addr", new Map([
    ["2.0.5", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-proxy-addr-2.0.5-34cbd64a2d81f4b1fd21e76f9f06c8a45299ee34/node_modules/proxy-addr/"),
      packageDependencies: new Map([
        ["forwarded", "0.1.2"],
        ["ipaddr.js", "1.9.0"],
        ["proxy-addr", "2.0.5"],
      ]),
    }],
  ])],
  ["forwarded", new Map([
    ["0.1.2", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-forwarded-0.1.2-98c23dab1175657b8c0573e8ceccd91b0ff18c84/node_modules/forwarded/"),
      packageDependencies: new Map([
        ["forwarded", "0.1.2"],
      ]),
    }],
  ])],
  ["ipaddr.js", new Map([
    ["1.9.0", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-ipaddr-js-1.9.0-37df74e430a0e47550fe54a2defe30d8acd95f65/node_modules/ipaddr.js/"),
      packageDependencies: new Map([
        ["ipaddr.js", "1.9.0"],
      ]),
    }],
  ])],
  ["range-parser", new Map([
    ["1.2.1", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-range-parser-1.2.1-3cf37023d199e1c24d1a55b84800c2f3e6468031/node_modules/range-parser/"),
      packageDependencies: new Map([
        ["range-parser", "1.2.1"],
      ]),
    }],
  ])],
  ["send", new Map([
    ["0.17.1", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-send-0.17.1-c1d8b059f7900f7466dd4938bdc44e11ddb376c8/node_modules/send/"),
      packageDependencies: new Map([
        ["debug", "2.6.9"],
        ["depd", "1.1.2"],
        ["destroy", "1.0.4"],
        ["encodeurl", "1.0.2"],
        ["escape-html", "1.0.3"],
        ["etag", "1.8.1"],
        ["fresh", "0.5.2"],
        ["http-errors", "1.7.3"],
        ["mime", "1.6.0"],
        ["ms", "2.1.1"],
        ["on-finished", "2.3.0"],
        ["range-parser", "1.2.1"],
        ["statuses", "1.5.0"],
        ["send", "0.17.1"],
      ]),
    }],
  ])],
  ["destroy", new Map([
    ["1.0.4", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-destroy-1.0.4-978857442c44749e4206613e37946205826abd80/node_modules/destroy/"),
      packageDependencies: new Map([
        ["destroy", "1.0.4"],
      ]),
    }],
  ])],
  ["mime", new Map([
    ["1.6.0", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-mime-1.6.0-32cd9e5c64553bd58d19a568af452acff04981b1/node_modules/mime/"),
      packageDependencies: new Map([
        ["mime", "1.6.0"],
      ]),
    }],
  ])],
  ["serve-static", new Map([
    ["1.14.1", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-serve-static-1.14.1-666e636dc4f010f7ef29970a88a674320898b2f9/node_modules/serve-static/"),
      packageDependencies: new Map([
        ["encodeurl", "1.0.2"],
        ["escape-html", "1.0.3"],
        ["parseurl", "1.3.3"],
        ["send", "0.17.1"],
        ["serve-static", "1.14.1"],
      ]),
    }],
  ])],
  ["utils-merge", new Map([
    ["1.0.1", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-utils-merge-1.0.1-9f95710f50a267947b2ccc124741c1028427e713/node_modules/utils-merge/"),
      packageDependencies: new Map([
        ["utils-merge", "1.0.1"],
      ]),
    }],
  ])],
  ["vary", new Map([
    ["1.1.2", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-vary-1.1.2-2299f02c6ded30d4a5961b0b9f74524a18f634fc/node_modules/vary/"),
      packageDependencies: new Map([
        ["vary", "1.1.2"],
      ]),
    }],
  ])],
  ["jsonwebtoken", new Map([
    ["8.5.1", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-jsonwebtoken-8.5.1-00e71e0b8df54c2121a1f26137df2280673bcc0d/node_modules/jsonwebtoken/"),
      packageDependencies: new Map([
        ["jws", "3.2.2"],
        ["lodash.includes", "4.3.0"],
        ["lodash.isboolean", "3.0.3"],
        ["lodash.isinteger", "4.0.4"],
        ["lodash.isnumber", "3.0.3"],
        ["lodash.isplainobject", "4.0.6"],
        ["lodash.isstring", "4.0.1"],
        ["lodash.once", "4.1.1"],
        ["ms", "2.1.2"],
        ["semver", "5.7.0"],
        ["jsonwebtoken", "8.5.1"],
      ]),
    }],
  ])],
  ["jws", new Map([
    ["3.2.2", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-jws-3.2.2-001099f3639468c9414000e99995fa52fb478304/node_modules/jws/"),
      packageDependencies: new Map([
        ["jwa", "1.4.1"],
        ["safe-buffer", "5.2.0"],
        ["jws", "3.2.2"],
      ]),
    }],
  ])],
  ["jwa", new Map([
    ["1.4.1", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-jwa-1.4.1-743c32985cb9e98655530d53641b66c8645b039a/node_modules/jwa/"),
      packageDependencies: new Map([
        ["buffer-equal-constant-time", "1.0.1"],
        ["ecdsa-sig-formatter", "1.0.11"],
        ["safe-buffer", "5.2.0"],
        ["jwa", "1.4.1"],
      ]),
    }],
  ])],
  ["buffer-equal-constant-time", new Map([
    ["1.0.1", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-buffer-equal-constant-time-1.0.1-f8e71132f7ffe6e01a5c9697a4c6f3e48d5cc819/node_modules/buffer-equal-constant-time/"),
      packageDependencies: new Map([
        ["buffer-equal-constant-time", "1.0.1"],
      ]),
    }],
  ])],
  ["ecdsa-sig-formatter", new Map([
    ["1.0.11", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-ecdsa-sig-formatter-1.0.11-ae0f0fa2d85045ef14a817daa3ce9acd0489e5bf/node_modules/ecdsa-sig-formatter/"),
      packageDependencies: new Map([
        ["safe-buffer", "5.2.0"],
        ["ecdsa-sig-formatter", "1.0.11"],
      ]),
    }],
  ])],
  ["lodash.includes", new Map([
    ["4.3.0", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-lodash-includes-4.3.0-60bb98a87cb923c68ca1e51325483314849f553f/node_modules/lodash.includes/"),
      packageDependencies: new Map([
        ["lodash.includes", "4.3.0"],
      ]),
    }],
  ])],
  ["lodash.isboolean", new Map([
    ["3.0.3", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-lodash-isboolean-3.0.3-6c2e171db2a257cd96802fd43b01b20d5f5870f6/node_modules/lodash.isboolean/"),
      packageDependencies: new Map([
        ["lodash.isboolean", "3.0.3"],
      ]),
    }],
  ])],
  ["lodash.isinteger", new Map([
    ["4.0.4", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-lodash-isinteger-4.0.4-619c0af3d03f8b04c31f5882840b77b11cd68343/node_modules/lodash.isinteger/"),
      packageDependencies: new Map([
        ["lodash.isinteger", "4.0.4"],
      ]),
    }],
  ])],
  ["lodash.isnumber", new Map([
    ["3.0.3", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-lodash-isnumber-3.0.3-3ce76810c5928d03352301ac287317f11c0b1ffc/node_modules/lodash.isnumber/"),
      packageDependencies: new Map([
        ["lodash.isnumber", "3.0.3"],
      ]),
    }],
  ])],
  ["lodash.isplainobject", new Map([
    ["4.0.6", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-lodash-isplainobject-4.0.6-7c526a52d89b45c45cc690b88163be0497f550cb/node_modules/lodash.isplainobject/"),
      packageDependencies: new Map([
        ["lodash.isplainobject", "4.0.6"],
      ]),
    }],
  ])],
  ["lodash.isstring", new Map([
    ["4.0.1", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-lodash-isstring-4.0.1-d527dfb5456eca7cc9bb95d5daeaf88ba54a5451/node_modules/lodash.isstring/"),
      packageDependencies: new Map([
        ["lodash.isstring", "4.0.1"],
      ]),
    }],
  ])],
  ["lodash.once", new Map([
    ["4.1.1", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-lodash-once-4.1.1-0dd3971213c7c56df880977d504c88fb471a97ac/node_modules/lodash.once/"),
      packageDependencies: new Map([
        ["lodash.once", "4.1.1"],
      ]),
    }],
  ])],
  ["semver", new Map([
    ["5.7.0", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-semver-5.7.0-790a7cf6fea5459bac96110b29b60412dc8ff96b/node_modules/semver/"),
      packageDependencies: new Map([
        ["semver", "5.7.0"],
      ]),
    }],
  ])],
  ["passport", new Map([
    ["0.4.0", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-passport-0.4.0-c5095691347bd5ad3b5e180238c3914d16f05811/node_modules/passport/"),
      packageDependencies: new Map([
        ["passport-strategy", "1.0.0"],
        ["pause", "0.0.1"],
        ["passport", "0.4.0"],
      ]),
    }],
  ])],
  ["passport-strategy", new Map([
    ["1.0.0", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-passport-strategy-1.0.0-b5539aa8fc225a3d1ad179476ddf236b440f52e4/node_modules/passport-strategy/"),
      packageDependencies: new Map([
        ["passport-strategy", "1.0.0"],
      ]),
    }],
  ])],
  ["pause", new Map([
    ["0.0.1", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-pause-0.0.1-1d408b3fdb76923b9543d96fb4c9dfd535d9cb5d/node_modules/pause/"),
      packageDependencies: new Map([
        ["pause", "0.0.1"],
      ]),
    }],
  ])],
  ["passport-jwt", new Map([
    ["4.0.0", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-passport-jwt-4.0.0-7f0be7ba942e28b9f5d22c2ebbb8ce96ef7cf065/node_modules/passport-jwt/"),
      packageDependencies: new Map([
        ["jsonwebtoken", "8.5.1"],
        ["passport-strategy", "1.0.0"],
        ["passport-jwt", "4.0.0"],
      ]),
    }],
  ])],
  ["rand-token", new Map([
    ["0.4.0", {
      packageLocation: path.resolve(__dirname, "../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-rand-token-0.4.0-1a565b6ad12d92dd4b30c4c4e5945e8aa24a5b3b/node_modules/rand-token/"),
      packageDependencies: new Map([
        ["rand-token", "0.4.0"],
      ]),
    }],
  ])],
  [null, new Map([
    [null, {
      packageLocation: path.resolve(__dirname, "./"),
      packageDependencies: new Map([
        ["body-parser", "1.19.0"],
        ["express", "4.17.1"],
        ["jsonwebtoken", "8.5.1"],
        ["passport", "0.4.0"],
        ["passport-jwt", "4.0.0"],
        ["rand-token", "0.4.0"],
      ]),
    }],
  ])],
]);

let locatorsByLocations = new Map([
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-body-parser-1.19.0-96b2709e57c9c4e09a6fd66a8fd979844f69f08a/node_modules/body-parser/", {"name":"body-parser","reference":"1.19.0"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-bytes-3.1.0-f6cf7933a360e0588fa9fde85651cdc7f805d1f6/node_modules/bytes/", {"name":"bytes","reference":"3.1.0"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-content-type-1.0.4-e138cc75e040c727b1966fe5e5f8c9aee256fe3b/node_modules/content-type/", {"name":"content-type","reference":"1.0.4"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-debug-2.6.9-5d128515df134ff327e90a4c93f4e077a536341f/node_modules/debug/", {"name":"debug","reference":"2.6.9"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-ms-2.0.0-5608aeadfc00be6c2901df5f9861788de0d597c8/node_modules/ms/", {"name":"ms","reference":"2.0.0"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-ms-2.1.1-30a5864eb3ebb0a66f2ebe6d727af06a09d86e0a/node_modules/ms/", {"name":"ms","reference":"2.1.1"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-ms-2.1.2-d09d1f357b443f493382a8eb3ccd183872ae6009/node_modules/ms/", {"name":"ms","reference":"2.1.2"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-depd-1.1.2-9bcd52e14c097763e749b274c4346ed2e560b5a9/node_modules/depd/", {"name":"depd","reference":"1.1.2"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-http-errors-1.7.2-4f5029cf13239f31036e5b2e55292bcfbcc85c8f/node_modules/http-errors/", {"name":"http-errors","reference":"1.7.2"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-http-errors-1.7.3-6c619e4f9c60308c38519498c14fbb10aacebb06/node_modules/http-errors/", {"name":"http-errors","reference":"1.7.3"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-inherits-2.0.3-633c2c83e3da42a502f52466022480f4208261de/node_modules/inherits/", {"name":"inherits","reference":"2.0.3"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-inherits-2.0.4-0fa2c64f932917c3433a0ded55363aae37416b7c/node_modules/inherits/", {"name":"inherits","reference":"2.0.4"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-setprototypeof-1.1.1-7e95acb24aa92f5885e0abef5ba131330d4ae683/node_modules/setprototypeof/", {"name":"setprototypeof","reference":"1.1.1"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-statuses-1.5.0-161c7dac177659fd9811f43771fa99381478628c/node_modules/statuses/", {"name":"statuses","reference":"1.5.0"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-toidentifier-1.0.0-7e1be3470f1e77948bc43d94a3c8f4d7752ba553/node_modules/toidentifier/", {"name":"toidentifier","reference":"1.0.0"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-iconv-lite-0.4.24-2022b4b25fbddc21d2f524974a474aafe733908b/node_modules/iconv-lite/", {"name":"iconv-lite","reference":"0.4.24"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-safer-buffer-2.1.2-44fa161b0187b9549dd84bb91802f9bd8385cd6a/node_modules/safer-buffer/", {"name":"safer-buffer","reference":"2.1.2"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-on-finished-2.3.0-20f1336481b083cd75337992a16971aa2d906947/node_modules/on-finished/", {"name":"on-finished","reference":"2.3.0"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-ee-first-1.1.1-590c61156b0ae2f4f0255732a158b266bc56b21d/node_modules/ee-first/", {"name":"ee-first","reference":"1.1.1"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-qs-6.7.0-41dc1a015e3d581f1621776be31afb2876a9b1bc/node_modules/qs/", {"name":"qs","reference":"6.7.0"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-raw-body-2.4.0-a1ce6fb9c9bc356ca52e89256ab59059e13d0332/node_modules/raw-body/", {"name":"raw-body","reference":"2.4.0"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-unpipe-1.0.0-b2bf4ee8514aae6165b4817829d21b2ef49904ec/node_modules/unpipe/", {"name":"unpipe","reference":"1.0.0"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-type-is-1.6.18-4e552cd05df09467dcbc4ef739de89f2cf37c131/node_modules/type-is/", {"name":"type-is","reference":"1.6.18"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-media-typer-0.3.0-8710d7af0aa626f8fffa1ce00168545263255748/node_modules/media-typer/", {"name":"media-typer","reference":"0.3.0"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-mime-types-2.1.24-b6f8d0b3e951efb77dedeca194cff6d16f676f81/node_modules/mime-types/", {"name":"mime-types","reference":"2.1.24"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-mime-db-1.40.0-a65057e998db090f732a68f6c276d387d4126c32/node_modules/mime-db/", {"name":"mime-db","reference":"1.40.0"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-express-4.17.1-4491fc38605cf51f8629d39c2b5d026f98a4c134/node_modules/express/", {"name":"express","reference":"4.17.1"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-accepts-1.3.7-531bc726517a3b2b41f850021c6cc15eaab507cd/node_modules/accepts/", {"name":"accepts","reference":"1.3.7"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-negotiator-0.6.2-feacf7ccf525a77ae9634436a64883ffeca346fb/node_modules/negotiator/", {"name":"negotiator","reference":"0.6.2"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-array-flatten-1.1.1-9a5f699051b1e7073328f2a008968b64ea2955d2/node_modules/array-flatten/", {"name":"array-flatten","reference":"1.1.1"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-content-disposition-0.5.3-e130caf7e7279087c5616c2007d0485698984fbd/node_modules/content-disposition/", {"name":"content-disposition","reference":"0.5.3"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-safe-buffer-5.1.2-991ec69d296e0313747d59bdfd2b745c35f8828d/node_modules/safe-buffer/", {"name":"safe-buffer","reference":"5.1.2"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-safe-buffer-5.2.0-b74daec49b1148f88c64b68d49b1e815c1f2f519/node_modules/safe-buffer/", {"name":"safe-buffer","reference":"5.2.0"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-cookie-0.4.0-beb437e7022b3b6d49019d088665303ebe9c14ba/node_modules/cookie/", {"name":"cookie","reference":"0.4.0"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-cookie-signature-1.0.6-e303a882b342cc3ee8ca513a79999734dab3ae2c/node_modules/cookie-signature/", {"name":"cookie-signature","reference":"1.0.6"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-encodeurl-1.0.2-ad3ff4c86ec2d029322f5a02c3a9a606c95b3f59/node_modules/encodeurl/", {"name":"encodeurl","reference":"1.0.2"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-escape-html-1.0.3-0258eae4d3d0c0974de1c169188ef0051d1d1988/node_modules/escape-html/", {"name":"escape-html","reference":"1.0.3"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-etag-1.8.1-41ae2eeb65efa62268aebfea83ac7d79299b0887/node_modules/etag/", {"name":"etag","reference":"1.8.1"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-finalhandler-1.1.2-b7e7d000ffd11938d0fdb053506f6ebabe9f587d/node_modules/finalhandler/", {"name":"finalhandler","reference":"1.1.2"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-parseurl-1.3.3-9da19e7bee8d12dff0513ed5b76957793bc2e8d4/node_modules/parseurl/", {"name":"parseurl","reference":"1.3.3"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-fresh-0.5.2-3d8cadd90d976569fa835ab1f8e4b23a105605a7/node_modules/fresh/", {"name":"fresh","reference":"0.5.2"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-merge-descriptors-1.0.1-b00aaa556dd8b44568150ec9d1b953f3f90cbb61/node_modules/merge-descriptors/", {"name":"merge-descriptors","reference":"1.0.1"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-methods-1.1.2-5529a4d67654134edcc5266656835b0f851afcee/node_modules/methods/", {"name":"methods","reference":"1.1.2"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-path-to-regexp-0.1.7-df604178005f522f15eb4490e7247a1bfaa67f8c/node_modules/path-to-regexp/", {"name":"path-to-regexp","reference":"0.1.7"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-proxy-addr-2.0.5-34cbd64a2d81f4b1fd21e76f9f06c8a45299ee34/node_modules/proxy-addr/", {"name":"proxy-addr","reference":"2.0.5"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-forwarded-0.1.2-98c23dab1175657b8c0573e8ceccd91b0ff18c84/node_modules/forwarded/", {"name":"forwarded","reference":"0.1.2"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-ipaddr-js-1.9.0-37df74e430a0e47550fe54a2defe30d8acd95f65/node_modules/ipaddr.js/", {"name":"ipaddr.js","reference":"1.9.0"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-range-parser-1.2.1-3cf37023d199e1c24d1a55b84800c2f3e6468031/node_modules/range-parser/", {"name":"range-parser","reference":"1.2.1"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-send-0.17.1-c1d8b059f7900f7466dd4938bdc44e11ddb376c8/node_modules/send/", {"name":"send","reference":"0.17.1"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-destroy-1.0.4-978857442c44749e4206613e37946205826abd80/node_modules/destroy/", {"name":"destroy","reference":"1.0.4"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-mime-1.6.0-32cd9e5c64553bd58d19a568af452acff04981b1/node_modules/mime/", {"name":"mime","reference":"1.6.0"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-serve-static-1.14.1-666e636dc4f010f7ef29970a88a674320898b2f9/node_modules/serve-static/", {"name":"serve-static","reference":"1.14.1"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-utils-merge-1.0.1-9f95710f50a267947b2ccc124741c1028427e713/node_modules/utils-merge/", {"name":"utils-merge","reference":"1.0.1"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-vary-1.1.2-2299f02c6ded30d4a5961b0b9f74524a18f634fc/node_modules/vary/", {"name":"vary","reference":"1.1.2"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-jsonwebtoken-8.5.1-00e71e0b8df54c2121a1f26137df2280673bcc0d/node_modules/jsonwebtoken/", {"name":"jsonwebtoken","reference":"8.5.1"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-jws-3.2.2-001099f3639468c9414000e99995fa52fb478304/node_modules/jws/", {"name":"jws","reference":"3.2.2"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-jwa-1.4.1-743c32985cb9e98655530d53641b66c8645b039a/node_modules/jwa/", {"name":"jwa","reference":"1.4.1"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-buffer-equal-constant-time-1.0.1-f8e71132f7ffe6e01a5c9697a4c6f3e48d5cc819/node_modules/buffer-equal-constant-time/", {"name":"buffer-equal-constant-time","reference":"1.0.1"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-ecdsa-sig-formatter-1.0.11-ae0f0fa2d85045ef14a817daa3ce9acd0489e5bf/node_modules/ecdsa-sig-formatter/", {"name":"ecdsa-sig-formatter","reference":"1.0.11"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-lodash-includes-4.3.0-60bb98a87cb923c68ca1e51325483314849f553f/node_modules/lodash.includes/", {"name":"lodash.includes","reference":"4.3.0"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-lodash-isboolean-3.0.3-6c2e171db2a257cd96802fd43b01b20d5f5870f6/node_modules/lodash.isboolean/", {"name":"lodash.isboolean","reference":"3.0.3"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-lodash-isinteger-4.0.4-619c0af3d03f8b04c31f5882840b77b11cd68343/node_modules/lodash.isinteger/", {"name":"lodash.isinteger","reference":"4.0.4"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-lodash-isnumber-3.0.3-3ce76810c5928d03352301ac287317f11c0b1ffc/node_modules/lodash.isnumber/", {"name":"lodash.isnumber","reference":"3.0.3"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-lodash-isplainobject-4.0.6-7c526a52d89b45c45cc690b88163be0497f550cb/node_modules/lodash.isplainobject/", {"name":"lodash.isplainobject","reference":"4.0.6"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-lodash-isstring-4.0.1-d527dfb5456eca7cc9bb95d5daeaf88ba54a5451/node_modules/lodash.isstring/", {"name":"lodash.isstring","reference":"4.0.1"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-lodash-once-4.1.1-0dd3971213c7c56df880977d504c88fb471a97ac/node_modules/lodash.once/", {"name":"lodash.once","reference":"4.1.1"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-semver-5.7.0-790a7cf6fea5459bac96110b29b60412dc8ff96b/node_modules/semver/", {"name":"semver","reference":"5.7.0"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-passport-0.4.0-c5095691347bd5ad3b5e180238c3914d16f05811/node_modules/passport/", {"name":"passport","reference":"0.4.0"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-passport-strategy-1.0.0-b5539aa8fc225a3d1ad179476ddf236b440f52e4/node_modules/passport-strategy/", {"name":"passport-strategy","reference":"1.0.0"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-pause-0.0.1-1d408b3fdb76923b9543d96fb4c9dfd535d9cb5d/node_modules/pause/", {"name":"pause","reference":"0.0.1"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-passport-jwt-4.0.0-7f0be7ba942e28b9f5d22c2ebbb8ce96ef7cf065/node_modules/passport-jwt/", {"name":"passport-jwt","reference":"4.0.0"}],
  ["../../../../../../Users/dev/Library/Caches/Yarn/v4/npm-rand-token-0.4.0-1a565b6ad12d92dd4b30c4c4e5945e8aa24a5b3b/node_modules/rand-token/", {"name":"rand-token","reference":"0.4.0"}],
  ["./", topLevelLocator],
]);
exports.findPackageLocator = function findPackageLocator(location) {
  let relativeLocation = normalizePath(path.relative(__dirname, location));

  if (!relativeLocation.match(isStrictRegExp))
    relativeLocation = `./${relativeLocation}`;

  if (location.match(isDirRegExp) && relativeLocation.charAt(relativeLocation.length - 1) !== '/')
    relativeLocation = `${relativeLocation}/`;

  let match;

  if (relativeLocation.length >= 169 && relativeLocation[168] === '/')
    if (match = locatorsByLocations.get(relativeLocation.substr(0, 169)))
      return blacklistCheck(match);

  if (relativeLocation.length >= 157 && relativeLocation[156] === '/')
    if (match = locatorsByLocations.get(relativeLocation.substr(0, 157)))
      return blacklistCheck(match);

  if (relativeLocation.length >= 156 && relativeLocation[155] === '/')
    if (match = locatorsByLocations.get(relativeLocation.substr(0, 156)))
      return blacklistCheck(match);

  if (relativeLocation.length >= 155 && relativeLocation[154] === '/')
    if (match = locatorsByLocations.get(relativeLocation.substr(0, 155)))
      return blacklistCheck(match);

  if (relativeLocation.length >= 151 && relativeLocation[150] === '/')
    if (match = locatorsByLocations.get(relativeLocation.substr(0, 151)))
      return blacklistCheck(match);

  if (relativeLocation.length >= 149 && relativeLocation[148] === '/')
    if (match = locatorsByLocations.get(relativeLocation.substr(0, 149)))
      return blacklistCheck(match);

  if (relativeLocation.length >= 147 && relativeLocation[146] === '/')
    if (match = locatorsByLocations.get(relativeLocation.substr(0, 147)))
      return blacklistCheck(match);

  if (relativeLocation.length >= 145 && relativeLocation[144] === '/')
    if (match = locatorsByLocations.get(relativeLocation.substr(0, 145)))
      return blacklistCheck(match);

  if (relativeLocation.length >= 143 && relativeLocation[142] === '/')
    if (match = locatorsByLocations.get(relativeLocation.substr(0, 143)))
      return blacklistCheck(match);

  if (relativeLocation.length >= 142 && relativeLocation[141] === '/')
    if (match = locatorsByLocations.get(relativeLocation.substr(0, 142)))
      return blacklistCheck(match);

  if (relativeLocation.length >= 141 && relativeLocation[140] === '/')
    if (match = locatorsByLocations.get(relativeLocation.substr(0, 141)))
      return blacklistCheck(match);

  if (relativeLocation.length >= 140 && relativeLocation[139] === '/')
    if (match = locatorsByLocations.get(relativeLocation.substr(0, 140)))
      return blacklistCheck(match);

  if (relativeLocation.length >= 139 && relativeLocation[138] === '/')
    if (match = locatorsByLocations.get(relativeLocation.substr(0, 139)))
      return blacklistCheck(match);

  if (relativeLocation.length >= 138 && relativeLocation[137] === '/')
    if (match = locatorsByLocations.get(relativeLocation.substr(0, 138)))
      return blacklistCheck(match);

  if (relativeLocation.length >= 137 && relativeLocation[136] === '/')
    if (match = locatorsByLocations.get(relativeLocation.substr(0, 137)))
      return blacklistCheck(match);

  if (relativeLocation.length >= 135 && relativeLocation[134] === '/')
    if (match = locatorsByLocations.get(relativeLocation.substr(0, 135)))
      return blacklistCheck(match);

  if (relativeLocation.length >= 133 && relativeLocation[132] === '/')
    if (match = locatorsByLocations.get(relativeLocation.substr(0, 133)))
      return blacklistCheck(match);

  if (relativeLocation.length >= 132 && relativeLocation[131] === '/')
    if (match = locatorsByLocations.get(relativeLocation.substr(0, 132)))
      return blacklistCheck(match);

  if (relativeLocation.length >= 131 && relativeLocation[130] === '/')
    if (match = locatorsByLocations.get(relativeLocation.substr(0, 131)))
      return blacklistCheck(match);

  if (relativeLocation.length >= 129 && relativeLocation[128] === '/')
    if (match = locatorsByLocations.get(relativeLocation.substr(0, 129)))
      return blacklistCheck(match);

  if (relativeLocation.length >= 127 && relativeLocation[126] === '/')
    if (match = locatorsByLocations.get(relativeLocation.substr(0, 127)))
      return blacklistCheck(match);

  if (relativeLocation.length >= 126 && relativeLocation[125] === '/')
    if (match = locatorsByLocations.get(relativeLocation.substr(0, 126)))
      return blacklistCheck(match);

  if (relativeLocation.length >= 125 && relativeLocation[124] === '/')
    if (match = locatorsByLocations.get(relativeLocation.substr(0, 125)))
      return blacklistCheck(match);

  if (relativeLocation.length >= 123 && relativeLocation[122] === '/')
    if (match = locatorsByLocations.get(relativeLocation.substr(0, 123)))
      return blacklistCheck(match);

  if (relativeLocation.length >= 121 && relativeLocation[120] === '/')
    if (match = locatorsByLocations.get(relativeLocation.substr(0, 121)))
      return blacklistCheck(match);

  if (relativeLocation.length >= 2 && relativeLocation[1] === '/')
    if (match = locatorsByLocations.get(relativeLocation.substr(0, 2)))
      return blacklistCheck(match);

  return null;
};


/**
 * Returns the module that should be used to resolve require calls. It's usually the direct parent, except if we're
 * inside an eval expression.
 */

function getIssuerModule(parent) {
  let issuer = parent;

  while (issuer && (issuer.id === '[eval]' || issuer.id === '<repl>' || !issuer.filename)) {
    issuer = issuer.parent;
  }

  return issuer;
}

/**
 * Returns information about a package in a safe way (will throw if they cannot be retrieved)
 */

function getPackageInformationSafe(packageLocator) {
  const packageInformation = exports.getPackageInformation(packageLocator);

  if (!packageInformation) {
    throw makeError(
      `INTERNAL`,
      `Couldn't find a matching entry in the dependency tree for the specified parent (this is probably an internal error)`
    );
  }

  return packageInformation;
}

/**
 * Implements the node resolution for folder access and extension selection
 */

function applyNodeExtensionResolution(unqualifiedPath, {extensions}) {
  // We use this "infinite while" so that we can restart the process as long as we hit package folders
  while (true) {
    let stat;

    try {
      stat = statSync(unqualifiedPath);
    } catch (error) {}

    // If the file exists and is a file, we can stop right there

    if (stat && !stat.isDirectory()) {
      // If the very last component of the resolved path is a symlink to a file, we then resolve it to a file. We only
      // do this first the last component, and not the rest of the path! This allows us to support the case of bin
      // symlinks, where a symlink in "/xyz/pkg-name/.bin/bin-name" will point somewhere else (like "/xyz/pkg-name/index.js").
      // In such a case, we want relative requires to be resolved relative to "/xyz/pkg-name/" rather than "/xyz/pkg-name/.bin/".
      //
      // Also note that the reason we must use readlink on the last component (instead of realpath on the whole path)
      // is that we must preserve the other symlinks, in particular those used by pnp to deambiguate packages using
      // peer dependencies. For example, "/xyz/.pnp/local/pnp-01234569/.bin/bin-name" should see its relative requires
      // be resolved relative to "/xyz/.pnp/local/pnp-0123456789/" rather than "/xyz/pkg-with-peers/", because otherwise
      // we would lose the information that would tell us what are the dependencies of pkg-with-peers relative to its
      // ancestors.

      if (lstatSync(unqualifiedPath).isSymbolicLink()) {
        unqualifiedPath = path.normalize(path.resolve(path.dirname(unqualifiedPath), readlinkSync(unqualifiedPath)));
      }

      return unqualifiedPath;
    }

    // If the file is a directory, we must check if it contains a package.json with a "main" entry

    if (stat && stat.isDirectory()) {
      let pkgJson;

      try {
        pkgJson = JSON.parse(readFileSync(`${unqualifiedPath}/package.json`, 'utf-8'));
      } catch (error) {}

      let nextUnqualifiedPath;

      if (pkgJson && pkgJson.main) {
        nextUnqualifiedPath = path.resolve(unqualifiedPath, pkgJson.main);
      }

      // If the "main" field changed the path, we start again from this new location

      if (nextUnqualifiedPath && nextUnqualifiedPath !== unqualifiedPath) {
        const resolution = applyNodeExtensionResolution(nextUnqualifiedPath, {extensions});

        if (resolution !== null) {
          return resolution;
        }
      }
    }

    // Otherwise we check if we find a file that match one of the supported extensions

    const qualifiedPath = extensions
      .map(extension => {
        return `${unqualifiedPath}${extension}`;
      })
      .find(candidateFile => {
        return existsSync(candidateFile);
      });

    if (qualifiedPath) {
      return qualifiedPath;
    }

    // Otherwise, we check if the path is a folder - in such a case, we try to use its index

    if (stat && stat.isDirectory()) {
      const indexPath = extensions
        .map(extension => {
          return `${unqualifiedPath}/index${extension}`;
        })
        .find(candidateFile => {
          return existsSync(candidateFile);
        });

      if (indexPath) {
        return indexPath;
      }
    }

    // Otherwise there's nothing else we can do :(

    return null;
  }
}

/**
 * This function creates fake modules that can be used with the _resolveFilename function.
 * Ideally it would be nice to be able to avoid this, since it causes useless allocations
 * and cannot be cached efficiently (we recompute the nodeModulePaths every time).
 *
 * Fortunately, this should only affect the fallback, and there hopefully shouldn't be a
 * lot of them.
 */

function makeFakeModule(path) {
  const fakeModule = new Module(path, false);
  fakeModule.filename = path;
  fakeModule.paths = Module._nodeModulePaths(path);
  return fakeModule;
}

/**
 * Normalize path to posix format.
 */

function normalizePath(fsPath) {
  fsPath = path.normalize(fsPath);

  if (process.platform === 'win32') {
    fsPath = fsPath.replace(backwardSlashRegExp, '/');
  }

  return fsPath;
}

/**
 * Forward the resolution to the next resolver (usually the native one)
 */

function callNativeResolution(request, issuer) {
  if (issuer.endsWith('/')) {
    issuer += 'internal.js';
  }

  try {
    enableNativeHooks = false;

    // Since we would need to create a fake module anyway (to call _resolveLookupPath that
    // would give us the paths to give to _resolveFilename), we can as well not use
    // the {paths} option at all, since it internally makes _resolveFilename create another
    // fake module anyway.
    return Module._resolveFilename(request, makeFakeModule(issuer), false);
  } finally {
    enableNativeHooks = true;
  }
}

/**
 * This key indicates which version of the standard is implemented by this resolver. The `std` key is the
 * Plug'n'Play standard, and any other key are third-party extensions. Third-party extensions are not allowed
 * to override the standard, and can only offer new methods.
 *
 * If an new version of the Plug'n'Play standard is released and some extensions conflict with newly added
 * functions, they'll just have to fix the conflicts and bump their own version number.
 */

exports.VERSIONS = {std: 1};

/**
 * Useful when used together with getPackageInformation to fetch information about the top-level package.
 */

exports.topLevel = {name: null, reference: null};

/**
 * Gets the package information for a given locator. Returns null if they cannot be retrieved.
 */

exports.getPackageInformation = function getPackageInformation({name, reference}) {
  const packageInformationStore = packageInformationStores.get(name);

  if (!packageInformationStore) {
    return null;
  }

  const packageInformation = packageInformationStore.get(reference);

  if (!packageInformation) {
    return null;
  }

  return packageInformation;
};

/**
 * Transforms a request (what's typically passed as argument to the require function) into an unqualified path.
 * This path is called "unqualified" because it only changes the package name to the package location on the disk,
 * which means that the end result still cannot be directly accessed (for example, it doesn't try to resolve the
 * file extension, or to resolve directories to their "index.js" content). Use the "resolveUnqualified" function
 * to convert them to fully-qualified paths, or just use "resolveRequest" that do both operations in one go.
 *
 * Note that it is extremely important that the `issuer` path ends with a forward slash if the issuer is to be
 * treated as a folder (ie. "/tmp/foo/" rather than "/tmp/foo" if "foo" is a directory). Otherwise relative
 * imports won't be computed correctly (they'll get resolved relative to "/tmp/" instead of "/tmp/foo/").
 */

exports.resolveToUnqualified = function resolveToUnqualified(request, issuer, {considerBuiltins = true} = {}) {
  // The 'pnpapi' request is reserved and will always return the path to the PnP file, from everywhere

  if (request === `pnpapi`) {
    return pnpFile;
  }

  // Bailout if the request is a native module

  if (considerBuiltins && builtinModules.has(request)) {
    return null;
  }

  // We allow disabling the pnp resolution for some subpaths. This is because some projects, often legacy,
  // contain multiple levels of dependencies (ie. a yarn.lock inside a subfolder of a yarn.lock). This is
  // typically solved using workspaces, but not all of them have been converted already.

  if (ignorePattern && ignorePattern.test(normalizePath(issuer))) {
    const result = callNativeResolution(request, issuer);

    if (result === false) {
      throw makeError(
        `BUILTIN_NODE_RESOLUTION_FAIL`,
        `The builtin node resolution algorithm was unable to resolve the module referenced by "${request}" and requested from "${issuer}" (it didn't go through the pnp resolver because the issuer was explicitely ignored by the regexp "null")`,
        {
          request,
          issuer,
        }
      );
    }

    return result;
  }

  let unqualifiedPath;

  // If the request is a relative or absolute path, we just return it normalized

  const dependencyNameMatch = request.match(pathRegExp);

  if (!dependencyNameMatch) {
    if (path.isAbsolute(request)) {
      unqualifiedPath = path.normalize(request);
    } else if (issuer.match(isDirRegExp)) {
      unqualifiedPath = path.normalize(path.resolve(issuer, request));
    } else {
      unqualifiedPath = path.normalize(path.resolve(path.dirname(issuer), request));
    }
  }

  // Things are more hairy if it's a package require - we then need to figure out which package is needed, and in
  // particular the exact version for the given location on the dependency tree

  if (dependencyNameMatch) {
    const [, dependencyName, subPath] = dependencyNameMatch;

    const issuerLocator = exports.findPackageLocator(issuer);

    // If the issuer file doesn't seem to be owned by a package managed through pnp, then we resort to using the next
    // resolution algorithm in the chain, usually the native Node resolution one

    if (!issuerLocator) {
      const result = callNativeResolution(request, issuer);

      if (result === false) {
        throw makeError(
          `BUILTIN_NODE_RESOLUTION_FAIL`,
          `The builtin node resolution algorithm was unable to resolve the module referenced by "${request}" and requested from "${issuer}" (it didn't go through the pnp resolver because the issuer doesn't seem to be part of the Yarn-managed dependency tree)`,
          {
            request,
            issuer,
          }
        );
      }

      return result;
    }

    const issuerInformation = getPackageInformationSafe(issuerLocator);

    // We obtain the dependency reference in regard to the package that request it

    let dependencyReference = issuerInformation.packageDependencies.get(dependencyName);

    // If we can't find it, we check if we can potentially load it from the packages that have been defined as potential fallbacks.
    // It's a bit of a hack, but it improves compatibility with the existing Node ecosystem. Hopefully we should eventually be able
    // to kill this logic and become stricter once pnp gets enough traction and the affected packages fix themselves.

    if (issuerLocator !== topLevelLocator) {
      for (let t = 0, T = fallbackLocators.length; dependencyReference === undefined && t < T; ++t) {
        const fallbackInformation = getPackageInformationSafe(fallbackLocators[t]);
        dependencyReference = fallbackInformation.packageDependencies.get(dependencyName);
      }
    }

    // If we can't find the path, and if the package making the request is the top-level, we can offer nicer error messages

    if (!dependencyReference) {
      if (dependencyReference === null) {
        if (issuerLocator === topLevelLocator) {
          throw makeError(
            `MISSING_PEER_DEPENDENCY`,
            `You seem to be requiring a peer dependency ("${dependencyName}"), but it is not installed (which might be because you're the top-level package)`,
            {request, issuer, dependencyName}
          );
        } else {
          throw makeError(
            `MISSING_PEER_DEPENDENCY`,
            `Package "${issuerLocator.name}@${issuerLocator.reference}" is trying to access a peer dependency ("${dependencyName}") that should be provided by its direct ancestor but isn't`,
            {request, issuer, issuerLocator: Object.assign({}, issuerLocator), dependencyName}
          );
        }
      } else {
        if (issuerLocator === topLevelLocator) {
          throw makeError(
            `UNDECLARED_DEPENDENCY`,
            `You cannot require a package ("${dependencyName}") that is not declared in your dependencies (via "${issuer}")`,
            {request, issuer, dependencyName}
          );
        } else {
          const candidates = Array.from(issuerInformation.packageDependencies.keys());
          throw makeError(
            `UNDECLARED_DEPENDENCY`,
            `Package "${issuerLocator.name}@${issuerLocator.reference}" (via "${issuer}") is trying to require the package "${dependencyName}" (via "${request}") without it being listed in its dependencies (${candidates.join(
              `, `
            )})`,
            {request, issuer, issuerLocator: Object.assign({}, issuerLocator), dependencyName, candidates}
          );
        }
      }
    }

    // We need to check that the package exists on the filesystem, because it might not have been installed

    const dependencyLocator = {name: dependencyName, reference: dependencyReference};
    const dependencyInformation = exports.getPackageInformation(dependencyLocator);
    const dependencyLocation = path.resolve(__dirname, dependencyInformation.packageLocation);

    if (!dependencyLocation) {
      throw makeError(
        `MISSING_DEPENDENCY`,
        `Package "${dependencyLocator.name}@${dependencyLocator.reference}" is a valid dependency, but hasn't been installed and thus cannot be required (it might be caused if you install a partial tree, such as on production environments)`,
        {request, issuer, dependencyLocator: Object.assign({}, dependencyLocator)}
      );
    }

    // Now that we know which package we should resolve to, we only have to find out the file location

    if (subPath) {
      unqualifiedPath = path.resolve(dependencyLocation, subPath);
    } else {
      unqualifiedPath = dependencyLocation;
    }
  }

  return path.normalize(unqualifiedPath);
};

/**
 * Transforms an unqualified path into a qualified path by using the Node resolution algorithm (which automatically
 * appends ".js" / ".json", and transforms directory accesses into "index.js").
 */

exports.resolveUnqualified = function resolveUnqualified(
  unqualifiedPath,
  {extensions = Object.keys(Module._extensions)} = {}
) {
  const qualifiedPath = applyNodeExtensionResolution(unqualifiedPath, {extensions});

  if (qualifiedPath) {
    return path.normalize(qualifiedPath);
  } else {
    throw makeError(
      `QUALIFIED_PATH_RESOLUTION_FAILED`,
      `Couldn't find a suitable Node resolution for unqualified path "${unqualifiedPath}"`,
      {unqualifiedPath}
    );
  }
};

/**
 * Transforms a request into a fully qualified path.
 *
 * Note that it is extremely important that the `issuer` path ends with a forward slash if the issuer is to be
 * treated as a folder (ie. "/tmp/foo/" rather than "/tmp/foo" if "foo" is a directory). Otherwise relative
 * imports won't be computed correctly (they'll get resolved relative to "/tmp/" instead of "/tmp/foo/").
 */

exports.resolveRequest = function resolveRequest(request, issuer, {considerBuiltins, extensions} = {}) {
  let unqualifiedPath;

  try {
    unqualifiedPath = exports.resolveToUnqualified(request, issuer, {considerBuiltins});
  } catch (originalError) {
    // If we get a BUILTIN_NODE_RESOLUTION_FAIL error there, it means that we've had to use the builtin node
    // resolution, which usually shouldn't happen. It might be because the user is trying to require something
    // from a path loaded through a symlink (which is not possible, because we need something normalized to
    // figure out which package is making the require call), so we try to make the same request using a fully
    // resolved issuer and throws a better and more actionable error if it works.
    if (originalError.code === `BUILTIN_NODE_RESOLUTION_FAIL`) {
      let realIssuer;

      try {
        realIssuer = realpathSync(issuer);
      } catch (error) {}

      if (realIssuer) {
        if (issuer.endsWith(`/`)) {
          realIssuer = realIssuer.replace(/\/?$/, `/`);
        }

        try {
          exports.resolveToUnqualified(request, realIssuer, {considerBuiltins});
        } catch (error) {
          // If an error was thrown, the problem doesn't seem to come from a path not being normalized, so we
          // can just throw the original error which was legit.
          throw originalError;
        }

        // If we reach this stage, it means that resolveToUnqualified didn't fail when using the fully resolved
        // file path, which is very likely caused by a module being invoked through Node with a path not being
        // correctly normalized (ie you should use "node $(realpath script.js)" instead of "node script.js").
        throw makeError(
          `SYMLINKED_PATH_DETECTED`,
          `A pnp module ("${request}") has been required from what seems to be a symlinked path ("${issuer}"). This is not possible, you must ensure that your modules are invoked through their fully resolved path on the filesystem (in this case "${realIssuer}").`,
          {
            request,
            issuer,
            realIssuer,
          }
        );
      }
    }
    throw originalError;
  }

  if (unqualifiedPath === null) {
    return null;
  }

  try {
    return exports.resolveUnqualified(unqualifiedPath, {extensions});
  } catch (resolutionError) {
    if (resolutionError.code === 'QUALIFIED_PATH_RESOLUTION_FAILED') {
      Object.assign(resolutionError.data, {request, issuer});
    }
    throw resolutionError;
  }
};

/**
 * Setups the hook into the Node environment.
 *
 * From this point on, any call to `require()` will go through the "resolveRequest" function, and the result will
 * be used as path of the file to load.
 */

exports.setup = function setup() {
  // A small note: we don't replace the cache here (and instead use the native one). This is an effort to not
  // break code similar to "delete require.cache[require.resolve(FOO)]", where FOO is a package located outside
  // of the Yarn dependency tree. In this case, we defer the load to the native loader. If we were to replace the
  // cache by our own, the native loader would populate its own cache, which wouldn't be exposed anymore, so the
  // delete call would be broken.

  const originalModuleLoad = Module._load;

  Module._load = function(request, parent, isMain) {
    if (!enableNativeHooks) {
      return originalModuleLoad.call(Module, request, parent, isMain);
    }

    // Builtins are managed by the regular Node loader

    if (builtinModules.has(request)) {
      try {
        enableNativeHooks = false;
        return originalModuleLoad.call(Module, request, parent, isMain);
      } finally {
        enableNativeHooks = true;
      }
    }

    // The 'pnpapi' name is reserved to return the PnP api currently in use by the program

    if (request === `pnpapi`) {
      return pnpModule.exports;
    }

    // Request `Module._resolveFilename` (ie. `resolveRequest`) to tell us which file we should load

    const modulePath = Module._resolveFilename(request, parent, isMain);

    // Check if the module has already been created for the given file

    const cacheEntry = Module._cache[modulePath];

    if (cacheEntry) {
      return cacheEntry.exports;
    }

    // Create a new module and store it into the cache

    const module = new Module(modulePath, parent);
    Module._cache[modulePath] = module;

    // The main module is exposed as global variable

    if (isMain) {
      process.mainModule = module;
      module.id = '.';
    }

    // Try to load the module, and remove it from the cache if it fails

    let hasThrown = true;

    try {
      module.load(modulePath);
      hasThrown = false;
    } finally {
      if (hasThrown) {
        delete Module._cache[modulePath];
      }
    }

    // Some modules might have to be patched for compatibility purposes

    for (const [filter, patchFn] of patchedModules) {
      if (filter.test(request)) {
        module.exports = patchFn(exports.findPackageLocator(parent.filename), module.exports);
      }
    }

    return module.exports;
  };

  const originalModuleResolveFilename = Module._resolveFilename;

  Module._resolveFilename = function(request, parent, isMain, options) {
    if (!enableNativeHooks) {
      return originalModuleResolveFilename.call(Module, request, parent, isMain, options);
    }

    let issuers;

    if (options) {
      const optionNames = new Set(Object.keys(options));
      optionNames.delete('paths');

      if (optionNames.size > 0) {
        throw makeError(
          `UNSUPPORTED`,
          `Some options passed to require() aren't supported by PnP yet (${Array.from(optionNames).join(', ')})`
        );
      }

      if (options.paths) {
        issuers = options.paths.map(entry => `${path.normalize(entry)}/`);
      }
    }

    if (!issuers) {
      const issuerModule = getIssuerModule(parent);
      const issuer = issuerModule ? issuerModule.filename : `${process.cwd()}/`;

      issuers = [issuer];
    }

    let firstError;

    for (const issuer of issuers) {
      let resolution;

      try {
        resolution = exports.resolveRequest(request, issuer);
      } catch (error) {
        firstError = firstError || error;
        continue;
      }

      return resolution !== null ? resolution : request;
    }

    throw firstError;
  };

  const originalFindPath = Module._findPath;

  Module._findPath = function(request, paths, isMain) {
    if (!enableNativeHooks) {
      return originalFindPath.call(Module, request, paths, isMain);
    }

    for (const path of paths) {
      let resolution;

      try {
        resolution = exports.resolveRequest(request, path);
      } catch (error) {
        continue;
      }

      if (resolution) {
        return resolution;
      }
    }

    return false;
  };

  process.versions.pnp = String(exports.VERSIONS.std);
};

exports.setupCompatibilityLayer = () => {
  // ESLint currently doesn't have any portable way for shared configs to specify their own
  // plugins that should be used (https://github.com/eslint/eslint/issues/10125). This will
  // likely get fixed at some point, but it'll take time and in the meantime we'll just add
  // additional fallback entries for common shared configs.

  for (const name of [`react-scripts`]) {
    const packageInformationStore = packageInformationStores.get(name);
    if (packageInformationStore) {
      for (const reference of packageInformationStore.keys()) {
        fallbackLocators.push({name, reference});
      }
    }
  }

  // Modern versions of `resolve` support a specific entry point that custom resolvers can use
  // to inject a specific resolution logic without having to patch the whole package.
  //
  // Cf: https://github.com/browserify/resolve/pull/174

  patchedModules.push([
    /^\.\/normalize-options\.js$/,
    (issuer, normalizeOptions) => {
      if (!issuer || issuer.name !== 'resolve') {
        return normalizeOptions;
      }

      return (request, opts) => {
        opts = opts || {};

        if (opts.forceNodeResolution) {
          return opts;
        }

        opts.preserveSymlinks = true;
        opts.paths = function(request, basedir, getNodeModulesDir, opts) {
          // Extract the name of the package being requested (1=full name, 2=scope name, 3=local name)
          const parts = request.match(/^((?:(@[^\/]+)\/)?([^\/]+))/);

          // make sure that basedir ends with a slash
          if (basedir.charAt(basedir.length - 1) !== '/') {
            basedir = path.join(basedir, '/');
          }
          // This is guaranteed to return the path to the "package.json" file from the given package
          const manifestPath = exports.resolveToUnqualified(`${parts[1]}/package.json`, basedir);

          // The first dirname strips the package.json, the second strips the local named folder
          let nodeModules = path.dirname(path.dirname(manifestPath));

          // Strips the scope named folder if needed
          if (parts[2]) {
            nodeModules = path.dirname(nodeModules);
          }

          return [nodeModules];
        };

        return opts;
      };
    },
  ]);
};

if (module.parent && module.parent.id === 'internal/preload') {
  exports.setupCompatibilityLayer();

  exports.setup();
}

if (process.mainModule === module) {
  exports.setupCompatibilityLayer();

  const reportError = (code, message, data) => {
    process.stdout.write(`${JSON.stringify([{code, message, data}, null])}\n`);
  };

  const reportSuccess = resolution => {
    process.stdout.write(`${JSON.stringify([null, resolution])}\n`);
  };

  const processResolution = (request, issuer) => {
    try {
      reportSuccess(exports.resolveRequest(request, issuer));
    } catch (error) {
      reportError(error.code, error.message, error.data);
    }
  };

  const processRequest = data => {
    try {
      const [request, issuer] = JSON.parse(data);
      processResolution(request, issuer);
    } catch (error) {
      reportError(`INVALID_JSON`, error.message, error.data);
    }
  };

  if (process.argv.length > 2) {
    if (process.argv.length !== 4) {
      process.stderr.write(`Usage: ${process.argv[0]} ${process.argv[1]} <request> <issuer>\n`);
      process.exitCode = 64; /* EX_USAGE */
    } else {
      processResolution(process.argv[2], process.argv[3]);
    }
  } else {
    let buffer = '';
    const decoder = new StringDecoder.StringDecoder();

    process.stdin.on('data', chunk => {
      buffer += decoder.write(chunk);

      do {
        const index = buffer.indexOf('\n');
        if (index === -1) {
          break;
        }

        const line = buffer.slice(0, index);
        buffer = buffer.slice(index + 1);

        processRequest(line);
      } while (true);
    });
  }
}
