const {
  CloudWatchClient,
  GetMetricStatisticsCommand
} = require("@aws-sdk/client-cloudwatch");

const client = new CloudWatchClient({
  region: "ap-south-1"
});

const endTime = new Date();
const startTime = new Date(endTime.getTime() - 15 * 60 * 1000);

const command = new GetMetricStatisticsCommand({
  Namespace: "AWS/EC2",
  MetricName: "CPUUtilization",

  Dimensions: [
    {
      Name: "InstanceId",
      Value: "i-0ecd1bda9cc2025e1"
    }
  ],

  StartTime: startTime,
  EndTime: endTime,

  Period: 300,
  Statistics: ["Average"]
});

async function testCloudWatch() {
  try {
    const response = await client.send(command);

    console.log("CloudWatch CPU Response:");
    console.log(JSON.stringify(response.Datapoints, null, 2));
  } catch (error) {
    console.error("CloudWatch Error:");
    console.error(error);
  }
}

testCloudWatch();
