const express = require("express");
const axios = require("axios");
const cors = require("cors");
require("dotenv").config();
const app = express();
app.use(cors({
  origin: "*"
}));
app.use(express.json());

app.post("/api/email",async(req,res)=>{
    const {email} = req.body;
    if(!email){
        return res.json({
            success:false,
            breaches:[],
            message:"Email is required"
        });
    }
    try{
        const response= await axios.get(`https://leakcheck.io/api/public?check=${email}`);
        const data = response.data;
        if(!data.success||!data.sources||data.sources.length==0){
           return res.json({
                success:true,
                breaches:[]
            });
          
        }
          const exposedData = data.fields?data.fields.join(","):"unknown";
        const simplified=data.sources.map(item=>({
            website:item.name||"unknown",
            date:item.date||"N/A",
            data:exposedData
        }));
        res.json({
            success:true,
            breaches:simplified
        });
    }catch(err){
        res.status(500).json({
            success:false,
            breaches:[],
            message:"Failed to fetch breach data"
        });
    }
});
app.get("/api/ip", async (req, res) => {
  try {
    let ip =
  req.headers["x-forwarded-for"]?.split(",")[0] ||
  req.socket.remoteAddress;

if (!ip || ip === "::1" || ip === "127.0.0.1") {
  // fallback for local dev
  const ipresponse = await axios.get("https://api.ipify.org?format=json");
  ip = ipresponse.data.ip;
}

    const geoResponse = await axios.get(
      `http://ip-api.com/json/${ip}`
    );
    const geoData = geoResponse.data;

    const reputationResponse = await axios.get(
      "https://api.abuseipdb.com/api/v2/check",
      {
        params: { ipAddress: ip },
        headers: {
          Key: process.env.ABUSE_IP_DB_KEY,
          Accept: "application/json"
        }
      }
    );

    const score =
      reputationResponse.data.data.abuseConfidenceScore;

    let reputation =
      score < 25 ? "Safe"
      : score < 75 ? "Suspicious"
      : "Malicious";
      

    res.json({
      success: true,
      ip: ip,
      location: geoData.country || "Unknown",
      region: geoData.regionName || "Unknown",
      isp: geoData.isp || "Unknown",
      reputation: reputation
    });

  } catch (err) {
    console.log(err.response?.data);
    console.log(reputationResponse.data);
    res.status(500).json({
      success: false,
      message: "Failed to fetch IP data"
    });
  }
});
app.post("/api/url",async (req,res)=>{
  const {url} = req.body;
  if (!url) {
    return res.status(400).json({
      success: false,
      threats: [],
      message: "URL is required"
    });
  }
  try{
  const submitResponse = await axios.post("https://www.virustotal.com/api/v3/urls",new URLSearchParams({url}),{
    headers:{
      "x-apikey":process.env.VIRUSTOTAL_API_KEY,
      "Content-Type":"application/x-www-form-urlencoded"
    }
  });
  const analysisId = submitResponse.data.data.id;
 let status = "queued";
let reportResponse;
let attempts=0;
while (status !== "completed"&& attempts < 10) {
  await new Promise(resolve => setTimeout(resolve, 2000));

  reportResponse = await axios.get(
    `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
    {
      headers: {
        "x-apikey": process.env.VIRUSTOTAL_API_KEY
      }
    }
  );

  status = reportResponse.data.data.attributes.status;
  attempts++;
  if (status !== "completed") {
  return res.status(500).json({
    success: false,
    message: "Scan timed out",
    threats: []
  });
}
}
  const attributes = reportResponse.data.data.attributes;
const results = attributes.results;
const threats=[];
for(const engine in results){
  const result = results[engine];
  if(result.category=="malicious"||result.category=="suspicious"){
    threats.push({
      type:result.result||"Threat",
      severity:result.category,
      engine_name:engine
    });
  }
}
res.json({
  success:true,
  threats
});
  }catch (err) {
  console.log("FULL ERROR:", err);
  
  console.log("STATUS:", err.response?.status);
  
  res.status(500).json({
    success: false,
    message: "Failed to scan URL"
  });
}

});
app.listen(3000,()=>{
    console.log("listening on port 3000");
})