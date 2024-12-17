const AWS = require("aws-sdk");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const docClient = new AWS.DynamoDB.DocumentClient();
const USERS_TABLE = process.env.USERS_TABLE;

module.exports.register = async (event) => {
  const { email, password } = JSON.parse(event.body);

  if (!email || !password) {
    return {
      statusCode: 400,
      body: JSON.stringify({ message: "Email and password are required" }),
    };
  }

  const tableName = process.env.USERS_TABLE || "Users";

  // Check if user already exists
  const params = {
    TableName: tableName,
    Key: {
      email,
    },
  };

  try {
    const data = await docClient.get(params).promise();
    if (data.Item) {
      return {
        statusCode: 400,
        body: JSON.stringify({ message: "User already exists" }),
      };
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Store user in DynamoDB
    const putParams = {
      TableName: USERS_TABLE,
      Item: {
        email,
        password: hashedPassword,
      },
    };

    await docClient.put(putParams).promise();

    return {
      statusCode: 201,
      body: JSON.stringify({ message: "User registered successfully" }),
    };
  } catch (err) {
    return {
      statusCode: 500,
      body: JSON.stringify({ message: "Server error", error: err.message }),
    };
  }
};

module.exports.login = async (event) => {
  const { email, password } = JSON.parse(event.body);

  if (!email || !password) {
    return {
      statusCode: 400,
      body: JSON.stringify({ message: "Email and password are required" }),
    };
  }

  const params = {
    TableName: USERS_TABLE,
    Key: {
      email,
    },
  };

  try {
    const data = await docClient.get(params).promise();
    if (!data.Item) {
      return {
        statusCode: 400,
        body: JSON.stringify({ message: "User not found" }),
      };
    }

    // Verify password
    const validPassword = await bcrypt.compare(password, data.Item.password);
    if (!validPassword) {
      return {
        statusCode: 400,
        body: JSON.stringify({ message: "Invalid credentials" }),
      };
    }

    // Generate JWT token
    const token = jwt.sign({ email }, "secretKey", { expiresIn: "1h" });

    return {
      statusCode: 200,
      body: JSON.stringify({ message: "Login successful", token }),
    };
  } catch (err) {
    return {
      statusCode: 500,
      body: JSON.stringify({ message: "Server error", error: err.message }),
    };
  }
};

module.exports.getAllUsers = async (event) => {
  const params = {
    TableName: process.env.USERS_TABLE,
  };

  try {
    const result = await docClient.scan(params).promise();

    // Return the list of users in the response body
    return {
      statusCode: 200,
      body: JSON.stringify({
        message: "Users retrieved successfully",
        users: result.Items,
      }),
    };
  } catch (error) {
    console.error(error);

    return {
      statusCode: 500,
      body: JSON.stringify({
        message: "Server error",
        error: error.message,
      }),
    };
  }
};

// Create a new Task
module.exports.createTask = async (event) => {
  const { taskId, title, description } = JSON.parse(event.body);
  const email = event.requestContext.authorizer.claims.email; // Get email from JWT token

  if (!taskId || !title || !description) {
    return {
      statusCode: 400,
      body: JSON.stringify({
        message: "taskId, title, and description are required",
      }),
    };
  }

  const params = {
    TableName: process.env.TASKS_TABLE,
    Item: {
      email,
      taskId,
      title,
      description,
      createdAt: new Date().toISOString(),
    },
  };

  try {
    await docClient.put(params).promise();
    return {
      statusCode: 201,
      body: JSON.stringify({ message: "Task created successfully" }),
    };
  } catch (err) {
    return {
      statusCode: 500,
      body: JSON.stringify({ message: "Server error", error: err.message }),
    };
  }
};

// Get all the tasks
module.exports.getTask = async (event) => {
  const { taskId } = event.pathParameters;
  const email = event.requestContext.authorizer.claims.email; // Get email from JWT token

  const params = {
    TableName: process.env.TASKS_TABLE,
    Key: {
      email,
      taskId,
    },
  };

  try {
    const data = await docClient.get(params).promise();
    if (!data.Item) {
      return {
        statusCode: 404,
        body: JSON.stringify({ message: "Task not found" }),
      };
    }
    return {
      statusCode: 200,
      body: JSON.stringify(data.Item),
    };
  } catch (err) {
    return {
      statusCode: 500,
      body: JSON.stringify({ message: "Server error", error: err.message }),
    };
  }
};

// Update a task
module.exports.updateTask = async (event) => {
  const { taskId } = event.pathParameters;
  const { title, description } = JSON.parse(event.body);
  const email = event.requestContext.authorizer.claims.email; // Get email from JWT token

  const params = {
    TableName: process.env.TASKS_TABLE,
    Key: {
      email,
      taskId,
    },
    UpdateExpression: "set title = :title, description = :description",
    ExpressionAttributeValues: {
      ":title": title,
      ":description": description,
    },
    ReturnValues: "UPDATED_NEW",
  };

  try {
    const data = await docClient.update(params).promise();
    if (!data.Attributes) {
      return {
        statusCode: 404,
        body: JSON.stringify({ message: "Task not found" }),
      };
    }
    return {
      statusCode: 200,
      body: JSON.stringify({
        message: "Task updated successfully",
        task: data.Attributes,
      }),
    };
  } catch (err) {
    return {
      statusCode: 500,
      body: JSON.stringify({ message: "Server error", error: err.message }),
    };
  }
};

// Deleta a task
module.exports.deleteTask = async (event) => {
  const { taskId } = event.pathParameters;
  const email = event.requestContext.authorizer.claims.email; // Get email from JWT token

  const params = {
    TableName: process.env.TASKS_TABLE,
    Key: {
      email,
      taskId,
    },
  };

  try {
    await docClient.delete(params).promise();
    return {
      statusCode: 200,
      body: JSON.stringify({ message: "Task deleted successfully" }),
    };
  } catch (err) {
    return {
      statusCode: 500,
      body: JSON.stringify({ message: "Server error", error: err.message }),
    };
  }
};
