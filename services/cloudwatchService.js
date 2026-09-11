const {
  CloudWatchClient,
  GetMetricStatisticsCommand
} = require("@aws-sdk/client-cloudwatch");

const client = new CloudWatchClient({
  region: process.env.AWS_REGION || "ap-south-1"
});

async function getEC2CPUUtilization(instanceId) {
  if (!instanceId) {
    throw new Error("EC2 instance ID is required");
  }

  const endTime = new Date();
  const startTime = new Date(endTime.getTime() - 15 * 60 * 1000);

  const command = new GetMetricStatisticsCommand({
    Namespace: "AWS/EC2",
    MetricName: "CPUUtilization",

    Dimensions: [
      {
        Name: "InstanceId",
        Value: instanceId
      }
    ],

    StartTime: startTime,
    EndTime: endTime,

    Period: 300,

    Statistics: ["Average"],

    Unit: "Percent"
  });

  const response = await client.send(command);

  if (!response.Datapoints || response.Datapoints.length === 0) {
    return null;
  }

  response.Datapoints.sort(
    (a, b) => new Date(b.Timestamp) - new Date(a.Timestamp)
  );

  const latest = response.Datapoints[0];

  return {
    instanceId,
    metric: "CPUUtilization",
    average: latest.Average,
    unit: latest.Unit,
    timestamp: latest.Timestamp
  };
}

module.exports = {
  getEC2CPUUtilization
};
