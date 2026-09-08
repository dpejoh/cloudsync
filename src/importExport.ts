import cloneDeep from "lodash/cloneDeep";
import QRCode from "qrcode";
import {
  COMMAND_URI,
  type QRExportType,
  type RemotelySavePluginSettings,
  type UriParams,
} from "./baseTypes";

export const exportQrCodeUri = async (
  settings: RemotelySavePluginSettings,
  currentVaultName: string,
  pluginVersion: string,
  exportFields: QRExportType
) => {
  const settings2 = cloneDeep(settings);
  const data = encodeURIComponent(JSON.stringify(settings2));
  const vault = encodeURIComponent(currentVaultName);
  const version = encodeURIComponent(pluginVersion);
  const rawUri = `obsidian://${COMMAND_URI}?func=settings&version=${version}&vault=${vault}&data=${data}`;
  const imgUri = await QRCode.toDataURL(rawUri);
  return {
    rawUri,
    imgUri,
  };
};

export interface ProcessQrCodeResultType {
  status: "error" | "ok";
  message: string;
  result?: RemotelySavePluginSettings;
}

export const parseUriByHand = (input: string) => {
  if (!input.startsWith(`obsidian://${COMMAND_URI}?func=settings&`)) {
    throw Error(`not valid string`);
  }

  const k = new URL(input);
  const output = Object.fromEntries(k.searchParams);
  return output;
};

export const importQrCodeUri = (
  inputParams: any,
  currentVaultName: string
): ProcessQrCodeResultType => {
  const params = inputParams as UriParams;
  if (
    params.func === undefined ||
    params.func !== "settings" ||
    params.vault === undefined ||
    params.data === undefined
  ) {
    return {
      status: "error",
      message: `the uri is not for exporting/importing settings: ${JSON.stringify(
        inputParams
      )}`,
    };
  }

  let settings = {} as RemotelySavePluginSettings;
  try {
    settings = JSON.parse(params.data);
  } catch (e) {
    return {
      status: "error",
      message: `errors while parsing settings: ${JSON.stringify(inputParams)}`,
    };
  }
  return {
    status: "ok",
    message: "ok",
    result: settings,
  };
};
