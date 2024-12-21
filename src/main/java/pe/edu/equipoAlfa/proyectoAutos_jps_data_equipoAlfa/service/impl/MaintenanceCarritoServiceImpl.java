package pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.service.impl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.dto.CarritoComprasListarDto;
import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.dto.CarritoComprasRegistrarDto;
import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.dto.VehiculosListarDto;
import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.entity.CarritoCompras;
import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.entity.CatVehiculos;
import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.entity.Clientes;
import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.entity.Vehiculos;
import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.repository.CarritoComprasRepository;
import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.repository.ClienteRepository;
import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.repository.VehiculoRepository;
import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.service.MaintenanceCarritoService;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

@Service
public class MaintenanceCarritoServiceImpl implements MaintenanceCarritoService {

    @Autowired
    CarritoComprasRepository carritoComprasRepository;

    @Autowired
    VehiculoRepository vehiculoRepository;

    @Autowired
    ClienteRepository clienteRepository;



    @Override
    public List<Vehiculos> getAllVehiculos() {
        Iterable<Vehiculos> iterable = vehiculoRepository.findAll();
        return StreamSupport.stream(iterable.spliterator(), false)
                .collect(Collectors.toList());
    }

    @Override
    public List<Clientes> getAllClientes() {
        Iterable<Clientes> iterable = clienteRepository.findAll();
        return StreamSupport.stream(iterable.spliterator(), false)
                .collect(Collectors.toList());
    }

    @Override
    public List<CarritoComprasListarDto> getAllCarritoCompras() {

        List<CarritoComprasListarDto> carritoComprasListarDtos = new ArrayList<>();
        Iterable<CarritoCompras> iterable = carritoComprasRepository.findAll();
        iterable.forEach(carrito -> {
            CarritoComprasListarDto carritoCompras = new CarritoComprasListarDto(

                    carrito.getIdCarrito(),
                    carrito.getVehiculo().getNombre(),
                    carrito.getCliente().getNombre(),
                    carrito.getCantidad(),
                    carrito.getDireccionEntrega(),
                    carrito.getMontoTotal(),
                    carrito.getLastUpdate()

            );
            carritoComprasListarDtos.add(carritoCompras);
        });
        return carritoComprasListarDtos;
    }

    @Override
    public Boolean realizarCompraCarrito(CarritoComprasRegistrarDto carritoComprasRegistrarDto) {
        try {
            // Validar que el vehículo exista
            Vehiculos vehiculo = vehiculoRepository.findById(carritoComprasRegistrarDto.idVehiculo())
                    .orElseThrow(() -> new IllegalArgumentException("Vehículo no encontrado con ID: " + carritoComprasRegistrarDto.idVehiculo()));

            // Validar que el cliente exista
            Clientes cliente = clienteRepository.findById(carritoComprasRegistrarDto.idUsuario())
                    .orElseThrow(() -> new IllegalArgumentException("Cliente no encontrado con ID: " + carritoComprasRegistrarDto.idUsuario()));


        // Validar que el precio no sea nulo
        if (vehiculo.getPrecio() == null) {
            throw new IllegalArgumentException("El precio del vehículo no puede ser nulo.");
        }

            // validar que la cantidad sea mayor a cero
            int cantidad = carritoComprasRegistrarDto.cantidad();

            if (carritoComprasRegistrarDto.cantidad() <= 0) {
                throw new IllegalArgumentException("La cantidad debe ser mayor a 0.");
            }


            Double montoTotal = vehiculo.getPrecio() * cantidad;

            // Verificar stock
            if (vehiculo.getStock() < cantidad) {
                throw new RuntimeException("Stock insuficiente");
            }

            // Actualizar stock
            vehiculo.setStock(vehiculo.getStock() - cantidad);
            vehiculoRepository.save(vehiculo);

            // registrar en carrito de comrpas
            CarritoCompras carrito = new CarritoCompras();

            carrito.setVehiculo(vehiculo);
            carrito.setCliente(cliente);
            carrito.setCantidad(cantidad);
            carrito.setDireccionEntrega(carritoComprasRegistrarDto.direccionEntrega());
            carrito.setMontoTotal(montoTotal);

            carritoComprasRepository.save(carrito);

            return true;

        }catch (Exception e) {

            // Log del error
            System.err.println("Error al realizar la compra: " + e.getMessage());
            return false;

        }

    }


    @Override
    public boolean deleteCarritoCompraById(int id) throws Exception {
        Optional<CarritoCompras> optional = carritoComprasRepository.findById(id);
        return optional.map(carrit -> {
            carritoComprasRepository.delete(carrit);
            return true;
        }).orElse(false);
    }




}
