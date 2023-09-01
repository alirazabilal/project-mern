const { ValidationError } = require("joi");

const errorHandler = (error, req, res, next) => {
  //default error

  let status = 500;
  let data = {
    message: "internal server error",
  };

  if (error instanceof ValidationError) {
    status: 400, (data.message = error.message);

    return res.status(status).json(data);
  }

  if (error.status) {
    status = error.status;
  }

  if (error.message) {
    data.message = error.message;
  }

  return res.status(status).json(data);
};

module.exports = errorHandler;
