import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './entities/user.entity';
import { Model } from 'mongoose';
import { CreateUserDto, LoginDto, RegisterUserDTO, UpdateAuthDto  } from './dto';
import * as bcryptjs from 'bcryptjs';

import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload';
import { LoginResponse } from './interfaces/login-response';
import { IsStrongPassword } from 'class-validator';
import { CheckTokenDTO } from './dto/check-token.dto';
import { Console } from 'console';
@Injectable()
export class AuthService {
  
  constructor(
    @InjectModel(User.name)
    private userModel: Model<User>,
    private jwtService: JwtService

  )     {} 

  

  async create(createUserDto: CreateUserDto) : Promise<User>{

    console.log(createUserDto);
//
   try{
    const {password,...userData}  = createUserDto;
    
    const newUser = new  this.userModel({
      password: bcryptjs.hashSync(password,10),
      ...userData
    });
    

    //    const newUser = new  this.userModel(createUserDto);
  //  return newUser.save();
  // 1- Encriptar la contraseña
  // 2- Guardar el usuario
  // 3- Generar el JWT
    await newUser.save();
    const {password:_,... user} = newUser.toJSON();
    return user;

    }
    catch (error){
    if (error.code == 11000){
      throw new  BadRequestException(`${createUserDto.email} already exists`)
    }
      throw new InternalServerErrorException('Something terrible happen!!!')
    console.log(error.code);
   }
  }

  async register(registerDTO:RegisterUserDTO): Promise<LoginResponse>{

   const createdUser  = await this.create({
      email: registerDTO.email,
      password: registerDTO.password,
      name: registerDTO.name,



    })

    
    return {
      user: createdUser,
      token: this.getJwtToken({id:createdUser._id})
    }
  }

  async login(loginDto: LoginDto) : Promise<LoginResponse>{
   const {email, password} = loginDto;
   const user = await this.userModel.findOne({email});
   if (!user){
    throw new UnauthorizedException('Not valid credentials - email');
   }
   console.log("LoginDTOPassword:" + password);
   console.log("User Password", user.password);
   if (!bcryptjs.compareSync(password, user.password)){
    throw new UnauthorizedException('Not valid credentials - password');
   }
  const {password:_, ...rest} = user.toJSON();
  return {
    user: rest,
    token: this.getJwtToken({id:user.id}),
  }


  }

  findAll(): Promise<User[]> {
    return this.userModel.find();
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  async findUserById(id:string){
    const user = await this.userModel.findById(id);
    const {password,...rest} = user.toJSON();
    return rest;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  getJwtToken(payload:JwtPayload){
    const token = this.jwtService.sign(payload);
    return token;

  }

 

}
