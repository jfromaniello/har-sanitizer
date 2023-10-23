// TypeScript type definition for HAR (HTTP Archive)
export type HarCookie = {
  name: string;
  value: string;
};

export type HarRequest = {
  method: string;
  url: string;
  httpVersion: string;
  headers: HarHeader[];
  queryString?: HarQueryParam[];
  postData?: HarPostData;
  cookies?: HarCookie[];
};

export type HarResponse = {
  status: number;
  statusText: string;
  httpVersion: string;
  headers: HarHeader[];
  content: HarContent;
  cookies?: HarCookie[];
};

export type HarHeader = {
  name: string;
  value: string;
};

export type HarQueryParam = {
  name: string;
  value: string;
};

export type HarPostData = {
  mimeType: string;
  params: HarPostParam[];
  text?: string;
};

export type HarPostParam = {
  name: string;
  value?: string;
  fileName?: string;
  contentType?: string;
};

export type HarContent = {
  size: number;
  mimeType: string;
  text: string;
  encoding?: string;
};

export type HarEntry = {
  startedDateTime: string;
  time: number;
  request: HarRequest;
  response: HarResponse;
  cache?: any;
  timings?: any;
  serverIPAddress?: string;
  connection?: string;
};

export type HarPage = {
  startedDateTime: string;
  id: string;
  title: string;
  pageTimings: {
    onLoad: number;
    onContentLoad: number;
  };
};

export type HarLog = {
  version: string;
  creator: {
    name: string;
    version: string;
  };
  entries: HarEntry[];
  pages?: HarPage[];
};

export type Har = {
  log: HarLog;
};
