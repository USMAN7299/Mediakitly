/*
 * Do not paste private API keys or webhook secrets in this file.
 * Adsterra publisher code is intentionally not enabled until you receive
 * the actual site/zone code from your Adsterra dashboard.
 */
window.MEDIAKITLY_MONETIZATION = {
  ads: {
    provider: "adsterra",
    enabled: false,
    freePlan: true,
    proPlan: true,
    placements: {
      homepage: "",
      guide: "",
      proLimited: ""
    }
  },
  plans: {
    free: { dailyOperations: 10, monthlyOperations: 100 },
    pro: { pricePkr: 499, dailyOperations: 100, monthlyOperations: 500 }
  }
};
