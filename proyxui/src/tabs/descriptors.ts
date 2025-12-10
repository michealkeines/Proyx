import { LiveInterceptTab } from "./LiveInterceptTab";
import { RequestReplayTab } from "./RequestReplayTab";
import { SiteMapTab } from "./SiteMapTab";
import type { TabDescriptor } from "../components/TabBar";

export const baseTabDescriptors: TabDescriptor[] = [
  { id: "site-map", title: "Site Map", component: SiteMapTab, priority: 1 },
  { id: "replay", title: "Request Replay", component: RequestReplayTab, priority: 2 },
  { id: "live-intercept", title: "Live Intercept", component: LiveInterceptTab, priority: 3 },
];
