const {
  getEC2CPUUtilization
} = require("./services/cloudwatchService");

async function test() {
  try {
    const result = await getEC2CPUUtilization(
      "i-0ecd1bda9cc2025e1"
    );

    console.log("EC2 CloudWatch Result:");
    console.log(result);
  } catch (error) {
    console.error("CloudWatch Service Error:");
    console.error(error);
  }
}

test();
