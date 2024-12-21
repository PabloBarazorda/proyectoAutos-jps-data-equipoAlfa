package pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.service.impl;

import jakarta.persistence.EntityNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
//import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.dto.ClientesDetallesDto;
import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.dto.*;
import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.entity.CatVehiculos;
import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.entity.Clientes;
import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.entity.Vehiculos;
import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.repository.CatVehiculoRepository;
import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.repository.ClienteRepository;
import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.repository.VehiculoRepository;
import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.service.MaintenanceService;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

@Service
public class MaintenanceServiceImpl implements MaintenanceService {

    @Autowired
    private ClienteRepository clienteRepository;

    @Autowired
    private VehiculoRepository vehiculoRepository;

    @Autowired
    private CatVehiculoRepository catVehiculoRepository;

    @Override
    public List<CatVehiculos> getAllCategorias() {
        Iterable<CatVehiculos> iterable = catVehiculoRepository.findAll();
        return StreamSupport.stream(iterable.spliterator(), false)
                .collect(Collectors.toList());
    }

    @Override
    public List<ClientesListarDto> getAllClients() {
        List<ClientesListarDto> clients = new ArrayList<>();
        Iterable<Clientes> iterable = clienteRepository.findAll();
        iterable.forEach(cliente -> {
            ClientesListarDto clientesListar = new ClientesListarDto(
                    cliente.getIdUsuario(),
                    cliente.getNombre(),
                    cliente.getApellidos(),
                    cliente.getDireccion(),
                    cliente.getCorreo(),
                    cliente.getTelefono(),
                    cliente.getFechaRegistro()
            );
            clients.add(clientesListar);
        });
        return clients;
    }

    @Override
    public ClientesDetallesDto getClienteDetalleById(Integer id) {

        Optional<Clientes> optional = clienteRepository.findById(id);
        return optional.map(cliente -> new ClientesDetallesDto(
                cliente.getIdUsuario(),
                cliente.getCorreo(),
                cliente.getUsername(),
                cliente.getNombre(),
                cliente.getApellidos(),
                cliente.getContrasenia(),
                cliente.getTelefono(),
                cliente.getDireccion(),
                cliente.getFechaRegistro()
        )).orElse(null);
    }

    @Override
    public void registrarCliente(ClientesRegistrarDto clientesRegistrarDto) {

        Clientes cliente = new Clientes();
        cliente.setCorreo(clientesRegistrarDto.correo());
        cliente.setUsername(clientesRegistrarDto.username());
        cliente.setNombre(clientesRegistrarDto.nombre());
        cliente.setApellidos(clientesRegistrarDto.apellidos());
        cliente.setContrasenia(clientesRegistrarDto.contrasenia());
        cliente.setTelefono(clientesRegistrarDto.telefono());
        cliente.setDireccion(clientesRegistrarDto.direccion());
        clienteRepository.save(cliente);

    }

    @Override
    public ClientesEditarDto getClientesEditarById(int id) {
        Optional<Clientes> optional = clienteRepository.findById(id);

        return optional.map(
                clientes -> new ClientesEditarDto(
                        clientes.getIdUsuario(),
                        clientes.getCorreo(),
                        clientes.getUsername(),
                        clientes.getNombre(),
                        clientes.getApellidos(),
                        clientes.getContrasenia(),
                        clientes.getTelefono(),
                        clientes.getDireccion(),
                        clientes.getFechaRegistro())

        ).orElse(null);

    }

    @Override
    public void postClientesEditarById(int id, ClientesEditarDto clientesEditarDto) {

        // Buscar por Id
        Clientes clientes = clienteRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("cliente no encontrado"));

        // Actualizar
        clientes.setCorreo(clientesEditarDto.correo());
        clientes.setUsername(clientesEditarDto.username());
        clientes.setNombre(clientesEditarDto.nombre());
        clientes.setApellidos(clientesEditarDto.apellidos());
        clientes.setContrasenia(clientesEditarDto.contrasenia());
        clientes.setTelefono(clientesEditarDto.telefono());
        clientes.setDireccion(clientesEditarDto.direccion());
        clientes.setFechaRegistro(new Date());

        // Guardar en DB
        clienteRepository.save(clientes);

    }

    @Override
    public void postClientesBorrarById(int id, ClientesBorrarDto clientesBorrarDto) {

        Optional<Clientes> optional = clienteRepository.findById(id);

        Clientes client = optional.orElseThrow(() -> new EntityNotFoundException("Cliente no existente"));

        clienteRepository.delete(client);

    }

    @Override
    public boolean deleteClientesById(int id) throws Exception {
        Optional<Clientes> optional = clienteRepository.findById(id);
        return optional.map(clien -> {
            clienteRepository.delete(clien);
            return true;
        }).orElse(false);
    }


    // VEHICULOS

    @Override
    public List<VehiculosListarDto> getAllVehiculos() {
        List<VehiculosListarDto> vehiculosDtoList = new ArrayList<>();
        Iterable<Vehiculos> iterable = vehiculoRepository.findAll();
        iterable.forEach(vehiculo -> {
            VehiculosListarDto vehiculosListar = new VehiculosListarDto(
                    vehiculo.getIdVehi(),
                    vehiculo.getNombre(),
                    vehiculo.getDetalles(),
                    vehiculo.getActivo(),
                    vehiculo.getFecha_lanzamiento(),
                    vehiculo.getStock(),
                    vehiculo.getPrecio(),
                    vehiculo.getCat_vehiculos().getTipo(),
                    vehiculo.getLastUpdate()
            );
            vehiculosDtoList.add(vehiculosListar);
        });
        return vehiculosDtoList;
    }


    // Categoria de Vehiculos

    @Override
    public CatVehiculoDetalles getCategoriaDetalleByVehiculoId(Integer id) {
        Vehiculos vehiculo = vehiculoRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Vehículo no encontrado: " + id));
        CatVehiculos categoria = vehiculo.getCat_vehiculos();
        return new CatVehiculoDetalles(
                categoria.getId_cat(),
                categoria.getMarca(),
                categoria.getTipo(),
                categoria.getActivo(),
                categoria.getTipo(),
                categoria.getDescripcion()
        );
    }

    @Override
    public void registrarVehiculo(VehiculosRegistrarDto vehiculosRegistrarDto) {
        Vehiculos vehiculo = new Vehiculos();
        vehiculo.setNombre(vehiculosRegistrarDto.nombre());
        vehiculo.setDetalles(vehiculosRegistrarDto.detalles());
        vehiculo.setActivo(vehiculosRegistrarDto.activo());
        vehiculo.setFecha_lanzamiento(vehiculosRegistrarDto.fecha_lanzamiento());
        vehiculo.setStock(vehiculosRegistrarDto.stock());
        vehiculo.setPrecio(vehiculosRegistrarDto.precio());

        CatVehiculos categoria = catVehiculoRepository.findById(vehiculosRegistrarDto.id_cat()) // Aquí usamos id_cat
                .orElseThrow(() -> new IllegalArgumentException("Categoría no encontrada: " + vehiculosRegistrarDto.id_cat()));
        vehiculo.setCat_vehiculos(categoria);

        vehiculo.setLastUpdate(new Date());

        vehiculoRepository.save(vehiculo);
    }

    @Override
    public void eliminarVehiculo(Integer idVehi) {
        vehiculoRepository.deleteById(idVehi);
    }

    @Override
    public VehiculosEditarDto getVehiculoById(Integer idVehi) {
        Vehiculos vehiculo = vehiculoRepository.findById(idVehi)
                .orElseThrow(() -> new IllegalArgumentException("Vehículo no encontrado: " + idVehi));
        return new VehiculosEditarDto(
                vehiculo.getIdVehi(),
                vehiculo.getNombre(),
                vehiculo.getDetalles(),
                vehiculo.getActivo(),
                vehiculo.getFecha_lanzamiento(),
                vehiculo.getStock(),
                vehiculo.getPrecio(),
                vehiculo.getCat_vehiculos().getId_cat()
        );
    }

    @Override
    public void actualizarVehiculo(VehiculosEditarDto vehiculosEditarDto) {
        Vehiculos vehiculo = vehiculoRepository.findById(vehiculosEditarDto.idVehi())
                .orElseThrow(() -> new IllegalArgumentException("Vehículo no encontrado: " + vehiculosEditarDto.idVehi()));

        vehiculo.setNombre(vehiculosEditarDto.nombre());
        vehiculo.setDetalles(vehiculosEditarDto.detalles());
        vehiculo.setActivo(vehiculosEditarDto.activo());
        vehiculo.setFecha_lanzamiento(vehiculosEditarDto.fecha_lanzamiento());
        vehiculo.setStock(vehiculosEditarDto.stock());
        vehiculo.setPrecio(vehiculosEditarDto.precio());

        CatVehiculos categoria = catVehiculoRepository.findById(vehiculosEditarDto.id_cat())
                .orElseThrow(() -> new IllegalArgumentException("Categoría no encontrada: " + vehiculosEditarDto.id_cat()));
        vehiculo.setCat_vehiculos(categoria);

        vehiculo.setLastUpdate(new Date());
        vehiculoRepository.save(vehiculo);
    }


}
