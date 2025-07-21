# Project Keystone - TODO List

This file tracks planned improvements and refactoring tasks for the Keystone backend.


- [ ] Instead of passing `access_token` in the request body for authenticated routes, use the standard `Authorization: Bearer <token>` header. This is a more secure and conventional approach for API authentication.