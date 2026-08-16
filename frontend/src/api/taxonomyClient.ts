import { request } from "./client";

export interface TaxonomyCategory {
  code: string;
  display_name: string;
  group: string;
  description: string;
  detection_methods: string[];
  masking_strategy: string;
  fingerprint_strategy: string;
  default_severity: string;
  internal_only: boolean;
  customer_notification_allowed: boolean;
  enabled: boolean;
  taxonomy_version: string;
  known_limitations: string[];
}

export const taxonomyApi = {
  list: () => request<{ taxonomy_version: string; categories: TaxonomyCategory[]; total: number }>("/sensitive-data-taxonomy"),
  version: () => request<{ taxonomy_version: string; category_count: number; enabled_category_count: number; registry_hash: string }>("/sensitive-data-taxonomy/version"),
};
